// tk-backup: minimal VLESS over WebSocket Worker (single file, no KV, no external fetch)
// BISECT TEST: cloudflare:sockets static import removed to find the cause of Error 1101
// Personal backup node for the user's 4 Railway VLESS nodes.
// The UUID is read from the UUID environment variable (same value as the Railway nodes).
// Subscription WS path: /?ed=2048

// import { connect } from 'cloudflare:sockets'; // TEMP removed for bisection test

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function userIDBytes(userID) {
  const hex = userID.replace(/-/g, '').toLowerCase();
  const arr = new Uint8Array(16);
  for (let i = 0; i < 16; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (err) {
    console.error('safeCloseWebSocket error', err);
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(base64Str);
    const buffer = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    return { earlyData: buffer.buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function concatUint8Arrays(a, b) {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

export default {
  async fetch(request, env) {
    try {
      const userID = (env.UUID || env.uuid || '').trim();
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        return await handleVlessWebSocket(request, userID);
      }
      return handleInfo(request, userID);
    } catch (err) {
      return new Response('Error: ' + err.message, { status: 500 });
    }
  },
};

function buildLink(host, userID) {
  return `vless://${userID}@${host}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=%2F%3Fed%3D2048#tk-backup`;
}

function handleInfo(request, userID) {
  const url = new URL(request.url);
  if (!userID) {
    return new Response('UUID environment variable is not set.', { status: 500 });
  }
  const link = buildLink(url.hostname, userID);
  if (url.pathname === '/' + userID || url.pathname === '/') {
    const html =
      '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>tk-backup</title></head><body>'
      + '<h1>tk-backup (Cloudflare Workers)</h1>'
      + '<p>Subscription link:</p><pre>' + link + '</pre>'
      + '<p>UUID: ' + userID + '</p>'
      + '<p>Address: ' + url.hostname + ' : 443, TLS on, WebSocket, path /?ed=2048</p>'
      + '</body></html>';
    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  return new Response('Not Found', { status: 404 });
}

async function handleVlessWebSocket(request, userID) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  const log = (info, event) => {
    console.log(`[${new Date().toISOString()}] ${info}`, event || '');
  };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  const remoteSocket = { value: null };
  const vlessResponseHeader = new Uint8Array([0, 0]);
  const udpState = { headerSent: false, isDns: false, address: '', port: 53 };
  const uuidBytes = userIDBytes(userID);

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk) {
      if (udpState.isDns) {
        return await handleUDPOutBound(udpState, chunk, webSocket, vlessResponseHeader, log);
      }
      if (remoteSocket.value) {
        const writer = remoteSocket.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }
      const {
        hasError, message, portRemote = 443, addressRemote = '',
        rawDataIndex, isUDP,
      } = processVlessHeader(chunk, uuidBytes);
      if (hasError) {
        safeCloseWebSocket(webSocket);
        throw new Error(message);
      }
      const rawClientData = chunk.slice(rawDataIndex);
      if (isUDP) {
        udpState.isDns = true;
        udpState.address = addressRemote;
        udpState.port = portRemote;
        return await handleUDPOutBound(udpState, rawClientData, webSocket, vlessResponseHeader, log);
      }
      await handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
    },
    close() { log('readableWebSocketStream closed'); },
    abort(reason) { log('readableWebSocketStream aborted', JSON.stringify(reason)); },
  })).catch((err) => {
    log('readableWebSocketStream pipeTo error', err);
    safeCloseWebSocket(webSocket);
  });

  return new Response(null, { status: 101, webSocket: client });
}

function processVlessHeader(vlessBuffer, uuidBytes) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const uuidArray = new Uint8Array(vlessBuffer.slice(1, 17));
  let isValidUser = true;
  for (let i = 0; i < 16; i++) {
    if (uuidArray[i] !== uuidBytes[i]) { isValidUser = false; break; }
  }
  if (!isValidUser) {
    return { hasError: true, message: 'invalid user' };
  }
  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  let isUDP = false;
  if (command === 1) {
    // TCP
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: `command ${command} is not supported` };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    case 2:
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const parts = [];
      for (let i = 0; i < 8; i++) {
        parts.push(new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).getUint16(i * 2).toString(16));
      }
      addressValue = parts.join(':');
      break;
    default:
      return { hasError: true, message: `invalid address type ${addressType}` };
  }
  if (!addressValue) {
    return { hasError: true, message: 'address is empty' };
  }
  return {
    hasError: false,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
    portRemote,
    addressRemote: addressValue,
    addressType,
  };
}

function makeReadableWebSocketStream(webSocket, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocket.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });
      webSocket.addEventListener('close', () => {
        safeCloseWebSocket(webSocket);
        controller.close();
      });
      webSocket.addEventListener('error', (err) => {
        log('webSocket error', err);
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {},
    cancel(reason) {
      log('ReadableStream canceled', JSON.stringify(reason));
      readableStreamCancel = true;
      safeCloseWebSocket(webSocket);
    },
  });
  return stream;
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }
  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
  let header = vlessResponseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (webSocket.readyState !== WS_READY_STATE_OPEN) {
        controller.error('webSocket.readyState is not open, maybe closed');
      }
      if (header) {
        webSocket.send(await new Blob([header, chunk]).arrayBuffer());
        header = null;
      } else {
        webSocket.send(chunk);
      }
      hasIncomingData = true;
    },
    close() {
      log('remoteSocketToWS closed, hasIncomingData = ' + hasIncomingData);
    },
    abort(reason) {
      console.error('remoteSocketToWS aborts', reason);
    },
  })).catch((error) => {
    console.error('remoteSocketToWS pipeTo error', error);
    safeCloseWebSocket(webSocket);
  });
  if (hasIncomingData === false && retry) {
    log('retry');
    retry();
  }
}

async function handleUDPOutBound(udpState, vlessData, webSocket, vlessResponseHeader, log) {
  const queries = [];
  let index = 0;
  while (index < vlessData.byteLength) {
    if (index + 2 > vlessData.byteLength) break;
    const len = new DataView(vlessData.slice(index, index + 2)).getUint16(0);
    if (index + 2 + len > vlessData.byteLength) break;
    queries.push(vlessData.slice(index + 2, index + 2 + len));
    index += 2 + len;
  }
  for (const query of queries) {
    const lenBuf = new Uint8Array(2);
    new DataView(lenBuf.buffer).setUint16(0, query.byteLength);
    const tcpSocket = connect({ hostname: udpState.address, port: udpState.port });
    const writer = tcpSocket.writable.getWriter();
    await writer.write(new Blob([lenBuf, query]));
    writer.releaseLock();
    const reader = tcpSocket.readable.getReader();
    let buf = new Uint8Array(0);
    let expectLen = -1;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf = concatUint8Arrays(buf, new Uint8Array(value));
        if (expectLen < 0 && buf.length >= 2) {
          expectLen = new DataView(buf.buffer.slice(0, 2)).getUint16(0);
        }
        if (expectLen >= 0 && buf.length >= 2 + expectLen) break;
      }
    } catch (err) {
      log('DNS read error', err);
    } finally {
      reader.releaseLock();
    }
    try { tcpSocket.close(); } catch (err) {}
    if (expectLen < 0) continue;
    const payload = buf.slice(2, 2 + expectLen);
    const out = new Uint8Array(2 + payload.byteLength);
    new DataView(out.buffer).setUint16(0, payload.byteLength);
    out.set(payload, 2);
    if (!udpState.headerSent) {
      webSocket.send(await new Blob([vlessResponseHeader, out]).arrayBuffer());
      udpState.headerSent = true;
    } else {
      webSocket.send(out);
    }
  }
}
