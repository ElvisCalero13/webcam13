const http = require('node:http');
const net = require('node:net');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');
const fs = require('node:fs');
const { getCameraCredentials } = require('./local-config');
const { discoverCameras } = require('./lan-discovery');
const { startLanNegotiation, startAvLogin, startAvVideo, setAvVideoQuality, getLanSessionStatus,
  probeAudioStartForVideo, closeSession, getLanVideoStatus, subscribeVideoFrames } = require('./lan-session');

const execFileAsync = promisify(execFile);
const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const AUDIO_PROBE_ENABLED = process.env.ENABLE_AUDIO_PROBE === '1';
const PACKAGE = 'com.juyi.newpublicapp';
const BRIDGE_PACKAGE = 'local.hdcamerapro.bridge';
const CONTROL_PORT = 18787;
const DEFAULT_ADB = 'C:\\platform-tools\\adb.exe';
const ADB = process.env.ADB_PATH || (fs.existsSync(DEFAULT_ADB) ? DEFAULT_ADB : 'adb');
const PAGE = path.join(__dirname, 'index.html');
const clients = new Set();
let captureBusy = false;
let captureTimer;
let preferredSerial = process.env.ANDROID_SERIAL || '';
let lastCaptureError = '';
let lastCaptureAt = 0;
let forwardedSerial = '';
let lanDiscoveryBusy = false;
const lanConnectOperations = new Map();
let audioProbeConsumed = false;

function sendJson(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(value));
}

function adb(args, options = {}) {
  return execFileAsync(ADB, args, { windowsHide: true, timeout: 10000, maxBuffer: 8 * 1024 * 1024, ...options });
}

async function connectedDevices() {
  const { stdout } = await adb(['devices']);
  return stdout.split(/\r?\n/).slice(1).map(line => line.trim().split(/\s+/))
    .filter(parts => parts.length > 1 && parts[1] === 'device').map(parts => parts[0]);
}

async function selectedSerial() {
  const devices = await connectedDevices();
  if (preferredSerial && devices.includes(preferredSerial)) return { devices, serial: preferredSerial };
  if (devices.length === 1) {
    preferredSerial = devices[0];
    return { devices, serial: preferredSerial };
  }
  if (devices.length > 1) return { devices, serial: '' };
  return { devices, serial: '' };
}

function deviceArgs(serial, args) { return ['-s', serial, ...args]; }

async function accessibilityEnabled(serial) {
  const { stdout } = await adb(deviceArgs(serial, ['shell', 'settings', 'get', 'secure', 'enabled_accessibility_services']));
  return stdout.toLowerCase().includes(`${BRIDGE_PACKAGE}/.remotecontrolservice`)
    || stdout.toLowerCase().includes(`${BRIDGE_PACKAGE}/${BRIDGE_PACKAGE}.remotecontrolservice`);
}

async function sendControl(serial, command, timeoutMs = 5000) {
  if (!(await accessibilityEnabled(serial))) {
    throw new Error('El servicio de accesibilidad del companion no está habilitado. Instala el APK y actívalo en Ajustes de Android.');
  }
  if (forwardedSerial !== serial) {
    await adb(deviceArgs(serial, ['forward', `tcp:${CONTROL_PORT}`, `tcp:${CONTROL_PORT}`]));
    forwardedSerial = serial;
  }
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: CONTROL_PORT });
    let response = '';
    const timeout = setTimeout(() => socket.destroy(new Error('Tiempo agotado: abre el companion y habilita su servicio de accesibilidad en Android.')), timeoutMs);
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.write(JSON.stringify(command) + '\n'));
    socket.on('data', chunk => {
      response += chunk;
      const end = response.indexOf('\n');
      if (end >= 0) {
        clearTimeout(timeout);
        socket.end();
        try {
          const result = JSON.parse(response.slice(0, end));
          if (result.ok) resolve(result);
          else reject(new Error(result.error || 'El servicio de accesibilidad rechazó el comando.'));
        } catch { reject(new Error('Respuesta inválida del companion Android.')); }
      }
    });
    socket.on('error', error => { clearTimeout(timeout); reject(new Error(`Control Android no disponible. Instala el companion y activa su servicio de accesibilidad. (${error.message})`)); });
    socket.on('close', () => clearTimeout(timeout));
  });
}

async function status() {
  try {
    const { devices, serial } = await selectedSerial();
    if (!devices.length) return { connected: false, message: 'Conecta el teléfono por USB y autoriza la depuración USB.', adb: ADB };
    if (!serial) return { connected: false, needsSelection: true, devices, message: 'Hay varios teléfonos conectados; selecciona uno.', adb: ADB };
    const [sizeResult, accessibilityResult] = await Promise.all([
      adb(deviceArgs(serial, ['shell', 'wm', 'size'])),
      accessibilityEnabled(serial).catch(() => false)
    ]);
    const { stdout } = sizeResult;
    const match = stdout.match(/(?:Override|Physical) size:\s*(\d+)x(\d+)/);
    let controlReady = false;
    let controlMessage = '';
    controlReady = accessibilityResult;
    if (!controlReady) controlMessage = 'Instala el companion Android y activa Control local HDCameraPro en Accesibilidad.';
    return { connected: true, serial, devices, width: match ? Number(match[1]) : null,
      height: match ? Number(match[2]) : null, package: PACKAGE, controlReady, controlMessage,
      captureError: lastCaptureError, lastCaptureAt, adb: ADB };
  } catch (error) {
    return { connected: false, message: `No se pudo ejecutar ADB (${error.message}). Revisa ADB_PATH.`, adb: ADB };
  }
}

function startCapture() {
  if (captureBusy || clients.size === 0) return;
  captureBusy = true;
  selectedSerial().then(({ serial }) => {
    if (!serial) throw new Error('No hay un teléfono seleccionado (revisa la conexión USB/ADB).');
    const child = spawn(ADB, deviceArgs(serial, ['exec-out', 'screencap', '-p']),
      { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = [];
    const errors = [];
    let size = 0;
    child.stdout.on('data', chunk => {
      size += chunk.length;
      if (size > 20 * 1024 * 1024) child.kill();
      else chunks.push(chunk);
    });
    child.stderr.on('data', chunk => errors.push(chunk));
    child.on('error', error => finish(error));
    child.on('close', code => {
      if (code !== 0) return finish(new Error(Buffer.concat(errors).toString('utf8').trim() || `ADB screencap terminó con código ${code}.`));
      const png = Buffer.concat(chunks);
      if (png.length < 8 || png.readUInt32BE(0) !== 0x89504e47) return finish(new Error('ADB no devolvió una imagen PNG válida.'));
      lastCaptureError = '';
      lastCaptureAt = Date.now();
      for (const res of clients) {
        if (res.destroyed || !res.writable) { clients.delete(res); continue; }
        try {
          res.write('--frame\r\nContent-Type: image/png\r\nContent-Length: ' + png.length + '\r\n\r\n');
          res.write(png);
          res.write('\r\n');
        } catch { clients.delete(res); }
      }
      finish();
    });
  }).catch(error => finish(error));

  function finish(error) {
    if (error) lastCaptureError = error.message;
    captureBusy = false;
  }
}

function readJson(req, limit = 2048) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > limit) { reject(new Error('Solicitud demasiado grande.')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('JSON inválido.')); }
    });
    req.on('error', reject);
  });
}

function connectLanDevice(deviceId) {
  const inFlight = lanConnectOperations.get(deviceId);
  if (inFlight) return inFlight;
  let session = null;
  const operation = (async () => {
    try {
      const { account, password } = getCameraCredentials();
      if (!password.trim()) throw new Error('Falta HDCAMERA_PASSWORD en backend-local/.env. Completa ese archivo y reinicia el backend.');
      session = await startLanNegotiation(deviceId);
      const av = await startAvLogin(session.sessionId, account, password);
      if (av.status !== 0) throw new Error(`La cámara respondió al inicio AV con estado ${av.status}.`);
      const video = await startAvVideo(session.sessionId);
      return { ok: true, sessionId: session.sessionId, ip: session.ip,
        state: 'video-start-sent', video,
        message: 'AV aceptado. Se envió el inicio de video; esperando cuadros de la cámara.' };
    } catch (error) {
      error.diagnostics ||= session ? getLanSessionStatus(session.sessionId) : null;
      throw error;
    }
  })();
  lanConnectOperations.set(deviceId, operation);
  operation.finally(() => {
    if (lanConnectOperations.get(deviceId) === operation) lanConnectOperations.delete(deviceId);
  }).catch(() => {});
  return operation;
}

function probeLanAudioSequence(deviceId) {
  if (audioProbeConsumed) {
    return Promise.reject(new Error('La prueba puntual de AUDIOSTART ya se ejecutó en este proceso.'));
  }
  if (lanConnectOperations.has(deviceId)) {
    return Promise.reject(new Error('Hay otra conexión en curso para esta cámara; espera a que termine.'));
  }
  audioProbeConsumed = true;
  let session = null;
  const operation = (async () => {
    try {
      const { account, password } = getCameraCredentials();
      if (!password.trim()) throw new Error('Falta HDCAMERA_PASSWORD en backend-local/.env.');
      session = await startLanNegotiation(deviceId);
      const av = await startAvLogin(session.sessionId, account, password);
      if (av.status !== 0) throw new Error(`La cámara respondió al inicio AV con estado ${av.status}.`);
      await startAvVideo(session.sessionId, { deferInfrared: true });
      return { ok: true, probe: await probeAudioStartForVideo(session.sessionId, 1000) };
    } catch (error) {
      error.diagnostics ||= session ? getLanSessionStatus(session.sessionId) : null;
      throw error;
    } finally {
      if (session) closeSession(session.sessionId);
    }
  })();
  lanConnectOperations.set(deviceId, operation);
  operation.finally(() => {
    if (lanConnectOperations.get(deviceId) === operation) lanConnectOperations.delete(deviceId);
  }).catch(() => {});
  return operation;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return fs.createReadStream(PAGE).pipe(res);
  }
  if (req.method === 'GET' && url.pathname === '/api/status') {
    try {
      const result = await Promise.race([
        status(),
        new Promise(resolve => setTimeout(() => resolve({ connected: false, message: 'El teléfono tardó en responder. Pulsa Actualizar para reintentar.', adb: ADB }), 5000))
      ]);
      return sendJson(res, 200, result);
    } catch (error) { return sendJson(res, 200, { connected: false, message: `No se pudo consultar el teléfono: ${error.message}`, adb: ADB }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/lan/discover') {
    if (lanDiscoveryBusy) return sendJson(res, 409, { error: 'Ya hay una búsqueda LAN en curso.' });
    lanDiscoveryBusy = true;
    try {
      const result = await discoverCameras({ durationMs: 2000 });
      return sendJson(res, 200, { ...result,
        audioProbeAvailable: AUDIO_PROBE_ENABLED && !audioProbeConsumed });
    } catch (error) {
      return sendJson(res, 503, { error: error.message });
    } finally {
      lanDiscoveryBusy = false;
    }
  }
  if (req.method === 'POST' && url.pathname === '/api/lan/negotiate') {
    try {
      const { deviceId } = await readJson(req);
      if (typeof deviceId !== 'string' || deviceId.length > 64) return sendJson(res, 400, { error: 'Dispositivo LAN no válido.' });
      const result = await startLanNegotiation(deviceId);
      return sendJson(res, 200, { ...result, message: 'La cámara respondió estado 1 al modo 1 y se envió modo 2. Node mantiene esta sesión provisional durante 120 s; el SID/send-path se valida al correlacionar el tráfico IOTC posterior.' });
    } catch (error) { return sendJson(res, 503, { error: error.message }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/lan/connect') {
    try {
      const { deviceId } = await readJson(req);
      if (typeof deviceId !== 'string' || deviceId.length > 64) return sendJson(res, 400, { error: 'Dispositivo LAN no válido.' });
      const result = await connectLanDevice(deviceId);
      return sendJson(res, 200, result);
    } catch (error) {
      const diagnostics = error.diagnostics || null;
      return sendJson(res, 503, { error: error.message, diagnostics });
    }
  }
  if (req.method === 'POST' && url.pathname === '/api/lan/audio-sequence-probe') {
    if (!AUDIO_PROBE_ENABLED || audioProbeConsumed) return sendJson(res, 404, { error: 'La prueba puntual está desactivada o ya se ejecutó.' });
    try {
      const { deviceId } = await readJson(req);
      if (typeof deviceId !== 'string' || deviceId.length > 64) return sendJson(res, 400, { error: 'Dispositivo LAN no válido.' });
      return sendJson(res, 200, await probeLanAudioSequence(deviceId));
    } catch (error) {
      return sendJson(res, 503, { error: error.message, diagnostics: error.diagnostics || null });
    }
  }
  if (req.method === 'POST' && url.pathname === '/api/lan/av-start') {
    try {
      const { sessionId, account, password } = await readJson(req);
      if (typeof sessionId !== 'string' || sessionId.length > 64) return sendJson(res, 400, { error: 'Sesión LAN no válida.' });
      const result = await startAvLogin(sessionId, account, password);
      const accepted = result.status === 0;
      return sendJson(res, 200, { ok: accepted, state: accepted ? 'av-login-accepted' : 'av-login-rejected',
        status: result.status, mode: result.mode,
        message: accepted ? 'La cámara aceptó el inicio AV. El video todavía requiere iniciar el control AV y recibir cuadros.'
          : `La cámara respondió al inicio AV con estado ${result.status}.` });
    } catch (error) { return sendJson(res, 503, { error: error.message }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/lan/video-start') {
    try {
      const { sessionId } = await readJson(req);
      if (typeof sessionId !== 'string' || sessionId.length > 64) return sendJson(res, 400, { error: 'Sesión AV no válida.' });
      const video = await startAvVideo(sessionId);
      return sendJson(res, 200, { ok: true, state: 'video-start-sent', video,
        message: 'Se enviaron los controles AV 255 y 511. Esperando los primeros cuadros de la cámara.' });
    } catch (error) { return sendJson(res, 503, { error: error.message }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/lan/video/quality') {
    try {
      const { sessionId, quality } = await readJson(req);
      if (typeof sessionId !== 'string' || sessionId.length > 64) return sendJson(res, 400, { error: 'Sesión de video no válida.' });
      if (!Number.isInteger(quality)) return sendJson(res, 400, { error: 'Calidad no válida.' });
      const result = await setAvVideoQuality(sessionId, quality);
      const label = ({ 1: '4K', 3: '2K', 5: '1080p' })[quality];
      return sendJson(res, 200, { ok: true, ...result,
        message: `Solicitud de ${label} enviada; llegó el acuse AVIOCTRL. Revisa la resolución H.264 que muestra el estado.` });
    } catch (error) { return sendJson(res, 503, { error: error.message }); }
  }
  if (req.method === 'GET' && url.pathname === '/api/lan/video/status') {
    const result = getLanVideoStatus(url.searchParams.get('id') || '');
    return result ? sendJson(res, 200, result) : sendJson(res, 404, { error: 'La sesión de video expiró o no existe.' });
  }
  if (req.method === 'GET' && url.pathname === '/api/lan/video.mjpg') {
    const sessionId = url.searchParams.get('id') || '';
    const current = getLanVideoStatus(sessionId);
    if (!current?.video?.started) return sendJson(res, 404, { error: 'El video no está iniciado en esta sesión.' });
    let unsubscribe;
    try {
      res.writeHead(200, { 'Content-Type': 'multipart/x-mixed-replace; boundary=frame',
        'Cache-Control': 'no-store', 'Connection': 'keep-alive' });
      unsubscribe = subscribeVideoFrames(sessionId, jpeg => {
        if (!jpeg) { unsubscribe?.(); res.end(); return; }
        if (res.destroyed || res.writableNeedDrain) return;
        res.write(`--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${jpeg.length}\r\n\r\n`);
        res.write(jpeg);
        res.write('\r\n');
      });
      res.on('close', () => unsubscribe?.());
    } catch (error) {
      if (!res.headersSent) return sendJson(res, 404, { error: error.message });
      res.end();
    }
    return;
  }
  if (req.method === 'GET' && url.pathname === '/api/lan/session') {
    const sessionId = url.searchParams.get('id') || '';
    const result = getLanSessionStatus(sessionId);
    return result ? sendJson(res, 200, result) : sendJson(res, 404, { error: 'La sesión LAN provisional expiró o no existe.' });
  }
  if (req.method === 'POST' && url.pathname === '/api/device') {
    try {
      const { serial } = await readJson(req);
      const { devices } = await selectedSerial();
      if (typeof serial !== 'string' || !devices.includes(serial)) return sendJson(res, 400, { error: 'Dispositivo no válido.' });
      preferredSerial = serial;
      return sendJson(res, 200, { ok: true, serial });
    } catch (error) { return sendJson(res, 400, { error: error.message }); }
  }
  if (req.method === 'GET' && url.pathname === '/stream.mjpg') {
    res.writeHead(200, { 'Content-Type': 'multipart/x-mixed-replace; boundary=frame', 'Cache-Control': 'no-store', 'Connection': 'keep-alive' });
    clients.add(res);
    if (!captureTimer) captureTimer = setInterval(startCapture, 250);
    startCapture();
    res.on('close', () => {
      clients.delete(res);
      if (clients.size === 0 && captureTimer) { clearInterval(captureTimer); captureTimer = null; }
    });
    return;
  }
  if (req.method === 'POST' && url.pathname === '/api/tap') {
    try {
      const { x, y } = await readJson(req);
      const { serial } = await selectedSerial();
      if (!serial) return sendJson(res, 409, { error: 'Selecciona un teléfono conectado primero.' });
      const { stdout } = await adb(deviceArgs(serial, ['shell', 'wm', 'size']));
      const match = stdout.match(/(?:Override|Physical) size:\s*(\d+)x(\d+)/);
      const width = match ? Number(match[1]) : 20000;
      const height = match ? Number(match[2]) : 20000;
      if (!Number.isInteger(x) || !Number.isInteger(y) || x < 0 || y < 0 || x >= width || y >= height) {
        return sendJson(res, 400, { error: 'Coordenadas inválidas.' });
      }
      await sendControl(serial, { type: 'tap', x, y });
      return sendJson(res, 200, { ok: true, serial, x, y, width, height });
    } catch (error) { return sendJson(res, 503, { error: error.message }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/swipe') {
    try {
      const { x1, y1, x2, y2, duration = 350 } = await readJson(req);
      const values = [x1, y1, x2, y2, duration];
      if (!values.every(Number.isInteger) || [x1, y1, x2, y2].some(v => v < 0 || v > 20000) || duration < 100 || duration > 2000) {
        return sendJson(res, 400, { error: 'Gesto o duración fuera de rango.' });
      }
      const { serial } = await selectedSerial();
      if (!serial) return sendJson(res, 409, { error: 'Selecciona un teléfono conectado primero.' });
      await sendControl(serial, { type: 'swipe', x1, y1, x2, y2, duration });
      return sendJson(res, 200, { ok: true, serial, x1, y1, x2, y2 });
    } catch (error) { return sendJson(res, 503, { error: error.message }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/key') {
    try {
      const { key } = await readJson(req);
      if (!['back', 'home'].includes(key)) return sendJson(res, 400, { error: 'Tecla no permitida.' });
      const { serial } = await selectedSerial();
      if (!serial) return sendJson(res, 409, { error: 'Selecciona un teléfono conectado primero.' });
      await sendControl(serial, { type: 'key', key });
      return sendJson(res, 200, { ok: true });
    } catch (error) { return sendJson(res, 503, { error: error.message }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/open') {
    try {
      const { serial } = await selectedSerial();
      if (!serial) return sendJson(res, 409, { error: 'Selecciona un teléfono conectado primero.' });
      await adb(deviceArgs(serial, ['shell', 'monkey', '-p', PACKAGE, '-c', 'android.intent.category.LAUNCHER', '1']));
      return sendJson(res, 200, { ok: true });
    } catch (error) { return sendJson(res, 503, { error: `No se pudo abrir HDCameraPro: ${error.message}` }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/open-bridge') {
    try {
      const { serial } = await selectedSerial();
      if (!serial) return sendJson(res, 409, { error: 'Selecciona un teléfono conectado primero.' });
      await adb(deviceArgs(serial, ['shell', 'monkey', '-p', BRIDGE_PACKAGE, '-c', 'android.intent.category.LAUNCHER', '1']));
      return sendJson(res, 200, { ok: true });
    } catch (error) { return sendJson(res, 503, { error: `No se pudo abrir el puente Android: ${error.message}` }); }
  }
  sendJson(res, 404, { error: 'Ruta no encontrada.' });
});

server.listen(PORT, HOST, () => console.log(`Beta HDCameraPro local lista: http://${HOST}:${PORT}`));
