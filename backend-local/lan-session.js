'use strict';

// Implementa el intercambio local de pre-sesión reconocido en libIOTCAPIs.so.
// Enviar modo 2 no demuestra por sí solo que exista un SID/send-path utilizable.
const dgram = require('node:dgram');
const { spawn } = require('node:child_process');
const { randomBytes, randomUUID } = require('node:crypto');
const os = require('node:os');
const { encodeDatagram, decodeDatagram } = require('./decode-pcap-video');
const { getDiscoveredDevice } = require('./lan-discovery');

const sessions = new Map();
const NEGOTIATION_TIMEOUT_MS = 2500;
const IOTC_READY_TIMEOUT_MS = 5000;
const SESSION_TTL_MS = 120000;
const MAX_SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;
const LAN_SEARCH_PORT = 32761;

function localIpv4For(address) {
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries || []) {
      if (entry.family === 'IPv4' && entry.address === address) return entry;
    }
  }
  return null;
}

function ipv4Number(ip) {
  return ip.split('.').reduce((value, part) => ((value << 8) | Number(part)) >>> 0, 0);
}

function numberIpv4(value) {
  return [24, 16, 8, 0].map(shift => (value >>> shift) & 0xff).join('.');
}

function broadcastFor(address, netmask) {
  const ip = ipv4Number(address);
  const mask = ipv4Number(netmask);
  return numberIpv4((ip & mask) | (~mask >>> 0));
}

function buildSessionProbe(uid, token, mode) {
  if (!/^[A-Za-z0-9]{1,20}$/.test(uid)) throw new Error('La identidad local del dispositivo no es válida.');
  if (!Buffer.isBuffer(token) || token.length !== 8 || ![1, 2].includes(mode)) throw new Error('Parámetros LAN inválidos.');
  const packet = Buffer.alloc(0x44);
  packet.writeUInt16LE(0x0204, 0);
  packet[2] = 0x14;
  packet.writeUInt16LE(0x34, 4);
  packet.writeUInt16LE(0x0601, 8);
  packet.writeUInt16LE(0x0021, 10);
  packet[15] = 0; // FUN_00114838(0, ..., mode, endpoint)
  Buffer.from(uid, 'ascii').copy(packet, 16, 0, 20);
  // local_560 contiene 0x0301052100000000; en little-endian el valor
  // 0x03010521 ocupa los bytes 0x34..0x37. Token: 0x38, modo: 0x40.
  packet.writeUInt32LE(0x03010521, 0x34);
  token.copy(packet, 0x38);
  packet.writeUInt32LE(mode, 0x40);
  packet[3] |= 0x02;
  return encodeDatagram(packet);
}

function parseSessionReply(raw, expectedUid, expectedToken) {
  const packet = decodeDatagram(raw);
  if (!packet || packet.length < 200 || packet.readUInt16LE(8) !== 0x0602) return null;
  const uid = packet.subarray(16, 36).toString('ascii').replace(/\0.*$/, '');
  if (uid !== expectedUid) return null;
  const token = Buffer.from(packet.subarray(188, 196));
  if (expectedToken && !token.equals(expectedToken)) return null;
  return { token, status: packet.readInt32LE(196) };
}

// Equivalente al primer mensaje de avClientStart2 para la versión observada
// (257 bytes por credencial), dentro de la envoltura de IOTC_Session_Write.
function buildAvLogin(account, password, token, sequence, channel = 0) {
  const accountBytes = Buffer.from(account, 'utf8');
  const passwordBytes = Buffer.from(password, 'utf8');
  if (accountBytes.length > 256 || passwordBytes.length > 256) {
    accountBytes.fill(0); passwordBytes.fill(0);
    throw new Error('La cuenta y contraseña deben ocupar como máximo 256 bytes UTF-8.');
  }
  const av = Buffer.alloc(562);
  av.writeUInt16LE(8, 2);
  av.writeUInt16LE(538, 16);
  // AVAPI_GetTimeMs usa el reloj monotónico desde el arranque del dispositivo,
  // no el tiempo transcurrido desde que se inició este proceso Node.
  av.writeUInt32LE(Math.floor(os.uptime() * 1000) >>> 0, 20);
  accountBytes.copy(av, 24);
  passwordBytes.copy(av, 24 + 257);
  av[24 + 514] = 1; // avClientStart2 fija param_7=1
  const opcodes = [4, 0x7fb, 0x1f, 0, 0x30000];
  opcodes.forEach((value, index) => av.writeUInt32LE(value, 24 + 518 + index * 4));
  accountBytes.fill(0); passwordBytes.fill(0);

  const packet = Buffer.alloc(28 + av.length);
  packet.writeUInt16LE(0x0204, 0);
  packet[2] = 0x14;
  packet[3] = 0x0a; // IOTC type 2 plus extension flag
  packet.writeUInt16LE(av.length + 12, 4);
  packet.writeUInt16LE(sequence & 0xffff, 6);
  packet.writeUInt16LE(0x0407, 8);
  packet.writeUInt16LE(0x0021, 10);
  packet.writeUInt16LE(token.readUInt16LE(0), 12); // 16 bits bajos del ID IOTC extendido abajo
  packet.writeUInt16LE(channel, 14);
  packet.writeUInt32LE(12, 16);
  token.copy(packet, 20);
  av.copy(packet, 28);
  av.fill(0);
  const wire = encodeDatagram(packet);
  packet.fill(0);
  return wire;
}

function parseAvLoginReply(packet) {
  if (!packet || packet.length < 61 || packet.readUInt16LE(8) !== 0x0408
      || packet[28] !== 0 || packet[29] !== 0x14) return null;
  return { status: packet.readInt32LE(52), mode: packet[60] };
}

function parseStreamControlReply(packet) {
  if (!packet || packet.length < 61 || packet.readUInt16LE(8) !== 0x0408
      || packet[29] !== 0x70 || packet.readUInt16LE(30) !== 0x000a
      || packet.readUInt32LE(52) !== 803) return null;
  return { status: packet.readInt8(56), mode: packet.readInt32BE(57) };
}

function parseAvIoCtrlAck(packet) {
  if (!packet || packet.length !== 52 || packet.readUInt16LE(8) !== 0x0408
      || packet[29] !== 0x71 || packet.readUInt16LE(30) !== 8
      || packet.readUInt16LE(44) !== 0) return null;
  return { outerSequence: packet.readUInt16LE(6), ioCtrlSequence: packet.readUInt32LE(32) };
}

function buildAvIoCtrl(command, data, token, sequence, channel = 0, ioCtrlSequence = 1) {
  if (!Buffer.isBuffer(data) || data.length > 0x3fc) throw new Error('Cuerpo AVIOCTRL no válido.');
  const av = Buffer.alloc(28 + data.length);
  av[1] = 0x70;
  av.writeUInt16LE(8, 2);
  av.writeUInt32LE(ioCtrlSequence >>> 0, 4);
  av.writeUInt16LE(data.length + 4, 16);
  av.writeUInt32LE(Math.floor(os.uptime() * 1000) >>> 0, 20);
  av.writeUInt32LE(command >>> 0, 24);
  data.copy(av, 28);

  const packet = Buffer.alloc(28 + av.length);
  packet.writeUInt16LE(0x0204, 0);
  packet[2] = 0x14;
  packet[3] = 0x0a;
  packet.writeUInt16LE(av.length + 12, 4);
  packet.writeUInt16LE(sequence & 0xffff, 6);
  packet.writeUInt16LE(0x0407, 8);
  packet.writeUInt16LE(0x0021, 10);
  packet.writeUInt16LE(token.readUInt16LE(0), 12);
  packet.writeUInt16LE(channel, 14);
  packet.writeUInt32LE(12, 16);
  token.copy(packet, 20);
  av.copy(packet, 28);
  av.fill(0);
  const wire = encodeDatagram(packet);
  packet.fill(0);
  return wire;
}

function buildAvIoCtrlReplyAck(active, reply) {
  // Formato observado en PCAPdroid: IOTC 0x0407, cabecera AV clase 0,
  // marker 0x71/type 10, misma secuencia AVIOCTRL de la respuesta, sin cuerpo.
  const sequence = active.sequence;
  const packet = Buffer.alloc(52);
  packet.writeUInt16LE(0x0204, 0);
  packet[2] = 0x14;
  packet[3] = 0x0a;
  packet.writeUInt16LE(36, 4);
  packet.writeUInt16LE(sequence, 6);
  packet.writeUInt16LE(0x0407, 8);
  packet.writeUInt16LE(0x0021, 10);
  packet.writeUInt16LE(active.token.readUInt16LE(0), 12);
  packet.writeUInt16LE(0, 14);
  packet.writeUInt32LE(12, 16);
  active.token.copy(packet, 20);
  packet[29] = 0x71;
  packet.writeUInt16LE(10, 30);
  packet.writeUInt32LE(reply.readUInt32LE(32), 32);
  active.sequence = (active.sequence + 1) & 0xffff;
  const wire = encodeDatagram(packet);
  packet.fill(0);
  return { wire, sequence };
}

function buildVideoFragmentAck(active, framePacket) {
  // La captura de la app nativa confirma recepción de datos con 0x0407,
  // clase 0/marker 8/tipo 8. El ID de bloque de 16 bits va en 46..47; el
  // cuerpo empieza en 48, seguido por frameNo en 52 y timestamp en 56.
  const sequence = active.sequence;
  const packet = Buffer.alloc(60);
  packet.writeUInt16LE(0x0204, 0);
  packet[2] = 0x14;
  packet[3] = 0x0a;
  packet.writeUInt16LE(44, 4);
  packet.writeUInt16LE(sequence, 6);
  packet.writeUInt16LE(0x0407, 8);
  packet.writeUInt16LE(0x0021, 10);
  packet.writeUInt16LE(active.token.readUInt16LE(0), 12);
  packet.writeUInt16LE(0, 14);
  packet.writeUInt32LE(12, 16);
  active.token.copy(packet, 20);
  packet[29] = 8;
  packet.writeUInt16LE(8, 30);
  framePacket.copy(packet, 46, 46, 48);
  packet.writeUInt32LE(framePacket.readUInt32LE(32), 52);
  packet.writeUInt32LE(Math.floor(os.uptime() * 1000) >>> 0, 56);
  active.sequence = (active.sequence + 1) & 0xffff;
  const wire = encodeDatagram(packet);
  packet.fill(0);
  return { wire, sequence };
}

function extractJpegs(video, chunk) {
  video.jpegBuffer = video.jpegBuffer.length
    ? Buffer.concat([video.jpegBuffer, chunk]) : Buffer.from(chunk);
  while (video.jpegBuffer.length >= 4) {
    const start = video.jpegBuffer.indexOf(Buffer.from([0xff, 0xd8]));
    if (start < 0) {
      video.jpegBuffer = video.jpegBuffer.subarray(Math.max(0, video.jpegBuffer.length - 1));
      return;
    }
    const end = video.jpegBuffer.indexOf(Buffer.from([0xff, 0xd9]), start + 2);
    if (end < 0) {
      if (start > 0) video.jpegBuffer = video.jpegBuffer.subarray(start);
      return;
    }
    const jpeg = Buffer.from(video.jpegBuffer.subarray(start, end + 2));
    video.jpegBuffer = video.jpegBuffer.subarray(end + 2);
    video.latestJpeg = jpeg;
    video.jpegFrames++;
    const now = Date.now();
    if (!video.fpsWindowStart) {
      video.fpsWindowStart = now;
      video.fpsWindowFrames = video.jpegFrames;
    } else if (now - video.fpsWindowStart >= 2000) {
      video.outputFps = Math.round((video.jpegFrames - video.fpsWindowFrames) * 1000
        / (now - video.fpsWindowStart));
      video.fpsWindowStart = now;
      video.fpsWindowFrames = video.jpegFrames;
    }
    for (const listener of video.listeners) {
      try { listener(jpeg); } catch { video.listeners.delete(listener); }
    }
  }
}

function h264SpsDimensions(frame) {
  const findStart = from => {
    for (let i = from; i + 3 < frame.length; i++) {
      if (frame[i] === 0 && frame[i + 1] === 0 && frame[i + 2] === 1) return { at: i, size: 3 };
      if (frame[i] === 0 && frame[i + 1] === 0 && frame[i + 2] === 0 && frame[i + 3] === 1) return { at: i, size: 4 };
    }
    return null;
  };
  let start = findStart(0);
  while (start) {
    const nalStart = start.at + start.size;
    const next = findStart(nalStart);
    const nalEnd = next ? next.at : frame.length;
    if (nalStart < nalEnd && (frame[nalStart] & 0x1f) === 7) {
      const rbsp = [];
      let zeros = 0;
      for (let i = nalStart + 1; i < nalEnd; i++) {
        const value = frame[i];
        if (zeros >= 2 && value === 3) { zeros = 0; continue; }
        rbsp.push(value);
        zeros = value === 0 ? zeros + 1 : 0;
      }
      let bit = 0;
      const readBit = () => {
        if (bit >= rbsp.length * 8) throw new Error('SPS truncado');
        return (rbsp[bit >> 3] >> (7 - (bit & 7))) & 1;
      };
      const readBits = count => {
        let value = 0;
        for (let i = 0; i < count; i++) value = value * 2 + readBit();
        return value;
      };
      const readUe = () => {
        let zerosBeforeOne = 0;
        while (readBit() === 0) {
          if (++zerosBeforeOne > 31) throw new Error('Exp-Golomb SPS inválido');
        }
        return zerosBeforeOne ? (2 ** zerosBeforeOne - 1) + readBits(zerosBeforeOne) : 0;
      };
      const readSe = () => { const code = readUe(); return code & 1 ? (code + 1) / 2 : -(code / 2); };
      const skipScalingList = size => {
        let lastScale = 8, nextScale = 8;
        for (let i = 0; i < size; i++) {
          if (nextScale !== 0) nextScale = (lastScale + readSe() + 256) % 256;
          if (nextScale !== 0) lastScale = nextScale;
        }
      };
      try {
        const profile = readBits(8);
        readBits(8); // constraint flags and reserved bits
        readBits(8); // level_idc
        readUe(); // seq_parameter_set_id
        let chromaFormat = 1;
        let separateColourPlane = 0;
        if ([100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135, 144].includes(profile)) {
          chromaFormat = readUe();
          if (chromaFormat > 3) return null;
          if (chromaFormat === 3) separateColourPlane = readBit();
          readUe(); readUe(); readBit();
          if (readBit()) {
            const lists = chromaFormat === 3 ? 12 : 8;
            for (let i = 0; i < lists; i++) if (readBit()) skipScalingList(i < 6 ? 16 : 64);
          }
        }
        readUe(); // log2_max_frame_num_minus4
        const picOrderCountType = readUe();
        if (picOrderCountType === 0) readUe();
        else if (picOrderCountType === 1) {
          readBit(); readSe(); readSe();
          const cycle = readUe();
          if (cycle > 256) return null;
          for (let i = 0; i < cycle; i++) readSe();
        }
        readUe(); readBit();
        const widthInMbs = readUe() + 1;
        const heightInMapUnits = readUe() + 1;
        const frameMbsOnly = readBit();
        if (!frameMbsOnly) readBit();
        readBit();
        let cropLeft = 0, cropRight = 0, cropTop = 0, cropBottom = 0;
        if (readBit()) { cropLeft = readUe(); cropRight = readUe(); cropTop = readUe(); cropBottom = readUe(); }
        const chromaArrayType = separateColourPlane ? 0 : chromaFormat;
        const subWidth = chromaArrayType === 1 || chromaArrayType === 2 ? 2 : 1;
        const subHeight = chromaArrayType === 1 ? 2 : 1;
        const cropUnitX = chromaArrayType === 0 ? 1 : subWidth;
        const cropUnitY = chromaArrayType === 0 ? 2 - frameMbsOnly : subHeight * (2 - frameMbsOnly);
        const width = widthInMbs * 16 - (cropLeft + cropRight) * cropUnitX;
        const height = heightInMapUnits * 16 * (2 - frameMbsOnly) - (cropTop + cropBottom) * cropUnitY;
        return width > 0 && height > 0 && width <= 8192 && height <= 8192 ? { width, height } : null;
      } catch { return null; }
    }
    start = next;
  }
  return null;
}

function createVideoPipeline(video) {
  const ffmpeg = process.env.FFMPEG_PATH || 'ffmpeg';
  const child = spawn(ffmpeg, ['-hide_banner', '-loglevel', 'info', '-err_detect', 'ignore_err',
    '-f', 'h264', '-i', 'pipe:0', '-an', '-vf', 'showinfo=checksum=0', '-c:v', 'mjpeg', '-q:v', '5',
    '-f', 'image2pipe', 'pipe:1'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  video.ffmpeg = child;
  child.stdout.on('data', chunk => extractJpegs(video, chunk));
  let stderrBuffer = '';
  child.stderr.on('data', chunk => {
    stderrBuffer = (stderrBuffer + chunk.toString('utf8')).slice(-8192);
    const lines = stderrBuffer.split(/\r?\n/);
    stderrBuffer = lines.pop() || '';
    for (const line of lines) {
      const size = line.match(/\bs:(\d+)x(\d+)\b/);
      if (size) {
        const resolution = `${size[1]}x${size[2]}`;
        if (video.h264Resolution && video.h264Resolution !== resolution) video.resolutionChanges++;
        video.h264Resolution = resolution;
      }
      if (/\b(error|invalid|non-existing PPS|corrupt|failed)\b/i.test(line)) {
        video.ffmpegError = line.trim().slice(0, 240);
      }
    }
  });
  child.on('error', error => { video.ffmpegError = `No se pudo iniciar FFmpeg: ${error.message}`; });
  child.on('close', code => {
    if (code && !video.ffmpegError) video.ffmpegError = `FFmpeg terminó con código ${code}.`;
  });
}

function finishVideoFrame(video, frame) {
  if (frame.parts.size === 0 || !frame.parts.has(0)) return;
  const indexes = [...frame.parts.keys()].sort((a, b) => a - b);
  if (!indexes.every((index, position) => index === position)) {
    video.incompleteFrames++;
    return;
  }
  const lastIndex = indexes[indexes.length - 1];
  const last = frame.parts.get(lastIndex);
  const size = lastIndex * 0x400 + last.length;
  if (size <= 0 || size > 4 * 1024 * 1024) { video.incompleteFrames++; return; }
  const bytes = Buffer.allocUnsafe(size);
  for (const index of indexes) frame.parts.get(index).copy(bytes, index * 0x400);
  video.assembledFrames++;
  video.assembledBytes += size;
  const dimensions = h264SpsDimensions(bytes);
  if (dimensions) {
    video.spsCount++;
    const resolution = `${dimensions.width}x${dimensions.height}`;
    if (video.h264Resolution && video.h264Resolution !== resolution) video.resolutionChanges++;
    video.h264Resolution = resolution;
  }
  if (!video.firstNalType && bytes.length >= 5 && bytes[0] === 0 && bytes[1] === 0
      && bytes[2] === 0 && bytes[3] === 1) video.firstNalType = bytes[4] & 0x1f;
  if (video.ffmpeg?.stdin?.writable) video.ffmpeg.stdin.write(bytes);
  bytes.fill(0);
}

function acceptVideoDatagram(active, packet) {
  const video = active.video;
  if (!video?.started || packet.length < 52 || packet[28] !== 1 || packet[29] !== 3) return false;
  video.candidateDatagrams++;
  // En los datagramas AV de subtipo 3, el token IOTC ocupa bytes 20..27.
  // Los bytes 16..19 pertenecen al prefijo de longitud/encabezado; compararlos
  // como parte del token descartaba cada cuadro real (validado en el PCAP).
  if ((packet[3] & 8) === 0 || !packet.subarray(20, 28).equals(active.token)) {
    video.rejectedSessionToken++;
    return true;
  }
  const frameNo = packet.readUInt32LE(32);
  const timestamp = packet.readUInt32LE(36);
  const index = packet.readUInt16LE(40);
  const flags = packet.readUInt16LE(42);
  const dataLength = packet.readUInt16LE(44);
  if (flags !== 0x10 || dataLength === 0 || dataLength > 0x400
      || 52 + dataLength > packet.length || index > 4095) {
    video.rejectedVideoLayout++;
    return true;
  }
  const acknowledgement = buildVideoFragmentAck(active, packet);
  video.videoAcksSent++;
  sendSessionDatagram(active, acknowledgement.wire).catch(() => { video.videoAckErrors++; });
  let frame = video.frames.get(frameNo);
  if (!frame) {
    frame = { frameNo, timestamp, firstAt: Date.now(), lastAt: Date.now(), parts: new Map() };
    video.frames.set(frameNo, frame);
  }
  frame.lastAt = Date.now();
  frame.parts.set(index, Buffer.from(packet.subarray(52, 52 + dataLength)));
  video.fragments++;
  video.bytesReceived += dataLength;
  video.lastVideoAt = Date.now();
  if (video.frames.size > 64) {
    const oldest = [...video.frames.values()].sort((a, b) => a.firstAt - b.firstAt)[0];
    video.frames.delete(oldest.frameNo);
    finishVideoFrame(video, oldest);
  }
  for (const [number, candidate] of video.frames) {
    if (Date.now() - candidate.lastAt >= 90) {
      video.frames.delete(number);
      finishVideoFrame(video, candidate);
    }
  }
  return true;
}

function acceptVideoAckReply(active, packet) {
  const video = active.video;
  // No consumir todos los 0x0408: aquí también viajan el login AV y la
  // respuesta GETSTREAMCTRL 803. Solo los ACKs de fragmento usan clase 1,
  // marker 9 y tipo 10.
  if (!video?.started || packet.length < 32 || packet.readUInt16LE(8) !== 0x0408
      || packet[28] !== 1 || packet[29] !== 9 || packet.readUInt16LE(30) !== 10) return false;
  video.videoAckReplyCandidates = (video.videoAckReplyCandidates || 0) + 1;
  video.videoAckReplyPackets = (video.videoAckReplyPackets || 0) + 1;
  if ((packet[3] & 8) !== 0 && packet.subarray(20, 28).equals(active.token)) {
    video.videoAckReplies++;
  }
  return true;
}

function sendSessionDatagram(session, wire) {
  return new Promise((resolve, reject) => {
    session.socket.send(wire, session.port, session.ip, error => {
      wire.fill(0);
      if (error) reject(error); else resolve();
    });
  });
}

async function sendAvIoCtrlAndWaitAck(active, command, data, timeoutMs = 1200) {
  const outerSequence = active.sequence;
  const ioCtrlSequence = active.ioCtrlSequence++;
  // El ACK 0x71 confirma el AVIOCTRL con su secuencia interna. La captura real
  // mostró que el outerSequence puede avanzar de forma independiente (p. ej.
  // se envió 61452 en outer=6/io=5 y el ACK llegó en outer=7/io=5).
  const key = `${ioCtrlSequence}`;
  const wire = buildAvIoCtrl(command, data, active.token, outerSequence, 0, ioCtrlSequence);
  active.sequence = (active.sequence + 1) & 0xffff;
  const ack = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (active.ioCtrlAcks?.get(key)?.timer !== timer) return;
      active.ioCtrlAcks.delete(key);
      reject(new Error(`No llegó el acuse AVIOCTRL para ${command} (seq ${outerSequence}/${ioCtrlSequence}).`));
    }, timeoutMs);
    active.ioCtrlAcks ||= new Map();
    active.ioCtrlAcks.set(key, { timer, resolve, reject, outerSequence, command });
  });
  try {
    await sendSessionDatagram(active, wire);
    await ack;
  } catch (error) {
    const pending = active.ioCtrlAcks?.get(key);
    if (pending) { clearTimeout(pending.timer); active.ioCtrlAcks.delete(key); }
    throw error;
  }
}

async function sendAvIoCtrlWithoutWaiting(active, command, data, ackTimeoutMs = 1200) {
  const outerSequence = active.sequence;
  const ioCtrlSequence = active.ioCtrlSequence++;
  const key = `${ioCtrlSequence}`;
  const wire = buildAvIoCtrl(command, data, active.token, outerSequence, 0, ioCtrlSequence);
  active.sequence = (active.sequence + 1) & 0xffff;
  active.ioCtrlAcks ||= new Map();
  const timer = setTimeout(() => {
    if (active.ioCtrlAcks?.get(key)?.timer === timer) active.ioCtrlAcks.delete(key);
  }, ackTimeoutMs);
  timer.unref?.();
  active.ioCtrlAcks.set(key, { timer, outerSequence, command, nonBlocking: true });
  try { await sendSessionDatagram(active, wire); }
  catch (error) {
    clearTimeout(timer);
    if (active.ioCtrlAcks.get(key)?.timer === timer) active.ioCtrlAcks.delete(key);
    throw error;
  }
}

function videoSummary(session) {
  const video = session.video;
  if (!video) return null;
  return { started: video.started, fragments: video.fragments, bytesReceived: video.bytesReceived,
    candidateDatagrams: video.candidateDatagrams, rejectedSessionToken: video.rejectedSessionToken,
    rejectedVideoLayout: video.rejectedVideoLayout,
    videoAcksSent: video.videoAcksSent || 0, videoAckReplies: video.videoAckReplies || 0,
    videoAckReplyCandidates: video.videoAckReplyCandidates || 0,
    videoAckReplyPackets: video.videoAckReplyPackets || 0,
    videoAckErrors: video.videoAckErrors || 0,
    assembledFrames: video.assembledFrames, assembledBytes: video.assembledBytes,
    incompleteFrames: video.incompleteFrames, jpegFrames: video.jpegFrames,
    h264Resolution: video.h264Resolution || null, outputFps: video.outputFps || 0,
    spsCount: video.spsCount || 0, resolutionChanges: video.resolutionChanges || 0,
    acknowledgedControls: video.acknowledgedControls || [],
    streamMode: video.streamMode ?? null, requestedQuality: video.requestedQuality ?? null,
    firstNalType: video.firstNalType, lastVideoAt: video.lastVideoAt || null,
    videoIdleMs: video.lastVideoAt ? Math.max(0, Date.now() - video.lastVideoAt) : null,
    ffmpegError: video.ffmpegError || null };
}

function touchSession(session) {
  const now = Date.now();
  session.hardExpiresAt ||= (session.createdAt || now) + MAX_SESSION_LIFETIME_MS;
  session.expiresAt = Math.min(now + SESSION_TTL_MS, session.hardExpiresAt);
  clearTimeout(session.expiryTimer);
  session.expiryTimer = setTimeout(() => {
    if (Date.now() < session.expiresAt) touchSession(session);
    else closeSession(session.sessionId);
  }, Math.max(1, session.expiresAt - now));
  session.expiryTimer.unref?.();
}

async function startAvVideo(sessionId, { deferInfrared = false } = {}) {
  const active = sessions.get(sessionId);
  if (!active || Date.now() >= active.expiresAt) throw new Error('La sesión AV caducó; vuelve a negociar.');
  if (active.state !== 'av-login-accepted') {
    if (active.state === 'iotc-session-closed') throw new Error('La cámara cerró la sesión IOTC antes de iniciar video.');
    throw new Error(`La cámara todavía no confirmó AV (estado ${active.state}).`);
  }
  if (active.video?.started) return videoSummary(active);
  const video = { started: true, frames: new Map(), fragments: 0, bytesReceived: 0,
    candidateDatagrams: 0, rejectedSessionToken: 0, rejectedVideoLayout: 0,
    videoAcksSent: 0, videoAckReplies: 0, videoAckReplyCandidates: 0,
    videoAckReplyPackets: 0, videoAckErrors: 0,
    assembledFrames: 0, assembledBytes: 0, incompleteFrames: 0, jpegFrames: 0,
    h264Resolution: null, outputFps: 0, spsCount: 0, resolutionChanges: 0,
    firstNalType: null, lastVideoAt: 0, jpegBuffer: Buffer.alloc(0), latestJpeg: null,
    listeners: new Set(), ffmpeg: null, ffmpegError: '' };
  active.video = video;
  touchSession(active);
  createVideoPipeline(video);
  try {
    // r2/b.run() hace el delay inicial de 2 bytes y luego empieza el cliente
    // AV. q2/a.I pide el modo con 802/803 antes de q2/b.q0() (delay 255 + START).
    // El cliente nativo escribe el delay inicial y continúa con GETSTREAMCTRL;
    // el acuse remoto de 255 no bloquea el orden 255 -> 802.
    await sendAvIoCtrlWithoutWaiting(active, 255, Buffer.alloc(2));
    const stream = await requestStreamControl(active);
    if (stream.status < 0) throw new Error(`La cámara rechazó GETSTREAMCTRL (803, estado ${stream.status}).`);
    video.streamMode = stream.mode;
    // q2/b.q0 comprueba la escritura local; luego inicia el hilo de recepción.
    // No espera respuestas AVIOCTRL entre el delay y START.
    await sendAvIoCtrlWithoutWaiting(active, 255, Buffer.alloc(8));
    await sendAvIoCtrlWithoutWaiting(active, 511, Buffer.alloc(8));
    if (!deferInfrared) {
      // La app consulta el estado infrarrojo al abrir la pantalla de video.
      // AUDIOSTART se mantiene desactivado en el flujo normal de la beta.
      await sendAvIoCtrlWithoutWaiting(active, 61452, Buffer.alloc(8));
    }
    active.state = 'video-start-sent';
    active.updatedAt = Date.now();
    return videoSummary(active);
  } catch (error) {
    video.started = false;
    video.ffmpeg?.stdin?.end();
    video.ffmpeg?.kill();
    throw new Error(`No se pudo enviar el inicio de video AV: ${error.message}`);
  }
}

async function setAvVideoQuality(sessionId, quality) {
  const active = sessions.get(sessionId);
  if (!active || Date.now() >= active.expiresAt) throw new Error('La sesión de video expiró; vuelve a conectar la cámara.');
  if (active.state !== 'video-start-sent' || !active.video?.started) {
    throw new Error('El video no está activo en esta sesión; conecta la cámara antes de cambiar la calidad.');
  }
  if (![1, 3, 5].includes(quality)) throw new Error('Calidad no válida.');
  // q2/a.b(stream=0, quality) envía SETSTREAMCTRL 800 en ocho bytes.
  const data = Buffer.alloc(8);
  data.writeUInt32LE(0, 0);
  data[4] = quality;
  await sendAvIoCtrlAndWaitAck(active, 800, data);
  active.video.requestedQuality = quality;
  return { quality, acknowledged: true, video: videoSummary(active) };
}

async function probeAudioStartForVideo(sessionId, dwellMs = 1000) {
  const active = sessions.get(sessionId);
  if (!active || Date.now() >= active.expiresAt || active.state !== 'video-start-sent'
      || !active.video?.started) throw new Error('La sesión de video no está lista para la prueba puntual.');
  const before = videoSummary(active);
  let audioStartAttempted = false;
  let audioStopSent = false;
  try {
    audioStartAttempted = true;
    await sendAvIoCtrlAndWaitAck(active, 768, Buffer.alloc(8));
    await sendAvIoCtrlAndWaitAck(active, 61452, Buffer.alloc(8));
    await new Promise(resolve => setTimeout(resolve, dwellMs));
  } finally {
    if (audioStartAttempted && sessions.get(sessionId) === active) {
      const stop = buildAvIoCtrl(769, Buffer.alloc(8), active.token, active.sequence, 0,
        active.ioCtrlSequence++);
      active.sequence = (active.sequence + 1) & 0xffff;
      await sendSessionDatagram(active, stop);
      audioStopSent = true;
    }
  }
  const after = videoSummary(active);
  return { audioStartAttempted, audioStopSent, audioStoredOrPlayed: false, dwellMs,
    fragmentsBefore: before.fragments, fragmentsAfter: after.fragments,
    bytesBefore: before.bytesReceived, bytesAfter: after.bytesReceived,
    framesBefore: before.assembledFrames, framesAfter: after.assembledFrames,
    jpegBefore: before.jpegFrames, jpegAfter: after.jpegFrames,
    acknowledgedControls: after.acknowledgedControls };
}

function requestStreamControl(active) {
  if (active.streamPending) return Promise.reject(new Error('Ya hay una consulta GETSTREAMCTRL pendiente.'));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (active.streamPending?.timer !== timer) return;
      active.streamPending = null;
      reject(new Error('No llegó GETSTREAMCTRL_RESP 803 después de solicitar el modo de video.'));
    }, 4000);
    active.streamPending = { timer, resolve, reject };
    const wire = buildAvIoCtrl(802, Buffer.alloc(8), active.token, active.sequence, 0, active.ioCtrlSequence++);
    active.sequence = (active.sequence + 1) & 0xffff;
    sendSessionDatagram(active, wire).catch(error => {
      if (active.streamPending?.timer !== timer) return;
      active.streamPending = null;
      clearTimeout(timer);
      reject(new Error(`No se pudo enviar GETSTREAMCTRL 802: ${error.message}`));
    });
  });
}

function subscribeVideoFrames(sessionId, listener) {
  const video = sessions.get(sessionId)?.video;
  if (!video) throw new Error('El video aún no se ha iniciado.');
  video.listeners.add(listener);
  if (video.latestJpeg) listener(video.latestJpeg);
  return () => video.listeners.delete(listener);
}

function getLanVideoStatus(sessionId) {
  const session = sessions.get(sessionId);
  if (!session || Date.now() >= session.expiresAt) return null;
  // Mientras una página consulta el estado del video, conserva la sesión IOTC
  // aunque haya una pausa temporal de paquetes. La fecha límite absoluta evita
  // dejar sockets vivos indefinidamente si el navegador queda abierto.
  if (session.video?.started && session.state !== 'iotc-session-closed') touchSession(session);
  return { sessionId, state: session.state, transportState: session.transportState,
    video: videoSummary(session) };
}

function endVideo(video) {
  if (!video) return;
  video.started = false;
  for (const frame of video.frames.values()) finishVideoFrame(video, frame);
  video.frames.clear();
  try { video.ffmpeg?.stdin?.end(); } catch { /* proceso ya cerrado */ }
  for (const listener of video.listeners) { try { listener(null); } catch { /* cliente cerrado */ } }
  video.listeners.clear();
  setTimeout(() => { try { video.ffmpeg?.kill(); } catch { /* proceso ya cerrado */ } }, 500).unref?.();
}

function describeTransportEvent(event) {
  const description = `${event.command}/${event.type}, ${event.length} B`;
  let meaning = event.meaning || '';
  if (event.sessionIdMatch === true) meaning += ', ID de sesión coincide';
  else if (event.sessionIdMatch === false) meaning += ', ID de sesión distinto';
  if (event.peerPort) meaning += `, puerto peer ${event.peerPort}`;
  if (event.avRetryToPeerPort) meaning += `, login repetido por ruta aprendida ${event.avRetryToPeerPort}`;
  if (event.avMarker !== undefined) {
    meaning += `, AV clase ${event.avClass}, marcador 0x${event.avMarker.toString(16)}, tipo ${event.avType}`;
    if (event.ioCtrlSequence !== undefined) meaning += `, seq AVIOCTRL ${event.ioCtrlSequence}`;
    if (event.avStatus !== undefined) meaning += `, estado ${event.avStatus}, modo ${event.avMode}`;
  }
  if (event.ackFor) meaning += `, acuse ${event.ackFor}`;
  return meaning ? `${description} (${meaning})` : description;
}

function startLanNegotiation(deviceId) {
  const device = getDiscoveredDevice(deviceId);
  if (!device) return Promise.reject(new Error('La búsqueda caducó. Vuelve a buscar la cámara en LAN.'));
  // Una cámara solo debe tener una sesión de prueba activa desde esta beta.
  // Al reintentar, cierra sockets AV antiguos para evitar mezclar respuestas.
  for (const [existingId, existing] of sessions) {
    if (existing.deviceId === deviceId) closeSession(existingId);
  }
  const nic = localIpv4For(device.localIp);
  if (!nic) return Promise.reject(new Error('La interfaz LAN de la búsqueda ya no está activa.'));

  // IOTC usa un ID aleatorio corto más datos de red para evitar colisiones.
  // Aquí se elige una pareja nueva de 64 bits; el manejador nativo la trata
  // como correlación de pre-sesión y la respuesta debe devolverla intacta.
  const token = randomBytes(8);
  const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  const sessionId = randomUUID();
  const result = { sessionId, deviceId, ip: device.ip, port: device.port,
    state: 'waiting-mode1', transportState: 'not-established', createdAt: Date.now() };
  const broadcast = broadcastFor(nic.address, nic.netmask);
  const ignoredReplies = [];

  return new Promise((resolve, reject) => {
    let settled = false;
    let mode1Retry;
    const timer = setTimeout(() => {
      const detail = ignoredReplies.length
        ? ` Sí hubo datagramas de la cámara, pero no coincidieron: ${ignoredReplies.join('; ')}.`
        : ` No llegó ninguna respuesta UDP de ${device.ip} al socket de esta laptop.`;
      finish(new Error(`La cámara no respondió a la petición LAN modo 1.${detail}`));
    }, NEGOTIATION_TIMEOUT_MS);
    const finish = (error, response, remote) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (mode1Retry) clearInterval(mode1Retry);
      if (error) { socket.close(); reject(error); return; }
      if (response.status !== 1) {
        socket.close();
        reject(new Error(`La cámara respondió con estado ${response.status}; no se creó la pre-sesión.`));
        return;
      }
      result.state = 'mode1-accepted';
      result.port = remote.port;
      result.updatedAt = Date.now();
      const mode2 = buildSessionProbe(device.uid, response.token, 2);
      const active = { ...result, socket, token: response.token, sequence: 0, ioCtrlSequence: 1,
        events: [], avPending: null, video: null, iotcReadyPending: null, ioCtrlAcks: new Map(),
        lastAvIoCtrlAck: null };
      sessions.set(sessionId, active);
      touchSession(active);
      const iotcReady = new Promise((ready, failed) => {
        const timer = setTimeout(() => {
          if (active.iotcReadyPending?.timer !== timer) return;
          active.iotcReadyPending = null;
          active.state = 'iotc-ready-timeout';
          active.updatedAt = Date.now();
          const observed = active.events.slice(-6).map(event => {
            const detail = describeTransportEvent(event);
            const ioctrl = event.ioCtrlCommand ? `, IOCTRL ${event.ioCtrlCommand}` : '';
            return `${detail}${ioctrl}`;
          }).join('; ');
          const suffix = observed ? ` Tráfico observado: ${observed}.`
            : ' No llegaron datagramas de respuesta al socket de esta sesión.';
          const error = new Error(`Se envió LAN modo 2, pero la cámara no confirmó la ruta IOTC (0x0428) dentro de 5 s.${suffix}`);
          error.diagnostics = publicSession(active);
          failed(error);
        }, IOTC_READY_TIMEOUT_MS);
        active.iotcReadyPending = { ready, failed, timer };
      });
      socket.send(mode2, remote.port, remote.address, sendError => {
        if (sendError) {
          if (active.iotcReadyPending) {
            clearTimeout(active.iotcReadyPending.timer);
            active.iotcReadyPending = null;
          }
          sessions.delete(sessionId);
          socket.close();
          reject(new Error(`No se pudo enviar la confirmación LAN modo 2: ${sendError.message}`));
          return;
        }
        result.state = 'mode2-sent-awaiting-iotc-result';
        if (active.state !== 'iotc-session-closed') active.state = result.state;
        if (active.transportState !== 'peer-route-observed' && active.transportState !== 'closed') {
          active.transportState = 'awaiting-peer-route';
        }
        active.updatedAt = Date.now();
        active.expiresAt = Date.now() + SESSION_TTL_MS;
        touchSession(active);
        iotcReady.then(() => resolve(publicSession(active)), error => reject(error));
      });
    };

    socket.on('error', error => finish(new Error(`Fallo UDP LAN: ${error.message}`)));
    socket.on('message', (raw, remote) => {
      if (remote.address !== device.ip) return;
      if (!settled) {
        const response = parseSessionReply(raw, device.uid, token);
        if (response) finish(null, response, remote);
        else {
          const packet = decodeDatagram(raw);
          if (packet && packet.length >= 10 && ignoredReplies.length < 4) {
            const type = `0x${packet.readUInt16LE(2).toString(16).padStart(4, '0')}`;
            const command = `0x${packet.readUInt16LE(8).toString(16).padStart(4, '0')}`;
            const uidMatch = packet.length >= 36
              && packet.subarray(16, 36).toString('ascii').replace(/\0.*$/, '') === device.uid;
            const tokenMatch = packet.length >= 196 && packet.subarray(188, 196).equals(token);
            const status = packet.length >= 200 ? `, estado ${packet.readInt32LE(196)}` : '';
            ignoredReplies.push(`${type}/${command}, ${packet.length} B desde ${remote.port}, UID ${uidMatch ? 'coincide' : 'distinto'}, token ${tokenMatch ? 'coincide' : 'distinto'}${status}`);
          }
        }
        return;
      }
      const packet = decodeDatagram(raw);
      const active = sessions.get(sessionId);
      if (!active || !packet || packet.length < 10) return;
      touchSession(active);
      if (acceptVideoDatagram(active, packet)) return;
      if (acceptVideoAckReply(active, packet)) return;
      const event = { type: `0x${packet.readUInt16LE(2).toString(16).padStart(4, '0')}`,
        command: `0x${packet.readUInt16LE(8).toString(16).padStart(4, '0')}`, length: packet.length };
      event.outerSequence = packet.readUInt16LE(6);
      if (packet.length >= 32 && event.command === '0x0408') {
        event.avClass = packet[28];
        event.avMarker = packet[29];
        event.avType = packet.readUInt16LE(30);
        if ((event.avMarker === 0x70 || event.avMarker === 0x71) && packet.length >= 36) {
          event.ioCtrlSequence = packet.readUInt32LE(32);
        }
      }
      // Interpretación basada en los dispatchers de libIOTCAPIs.so. Son pistas
      // del estado IOTC, no una confirmación de que el login AV se haya aceptado.
      event.peerPort = remote.port;
      if ((event.command === '0x0428' || event.command === '0x0418')
          && (packet[3] & 8) !== 0 && packet.length >= 24) {
        event.sessionIdMatch = packet.readUInt32LE(16) === active.token.readUInt32LE(0)
          && packet.readUInt32LE(20) === active.token.readUInt32LE(4);
      }
      if (packet.length >= 56 && packet[29] === 0x70 && packet.readUInt16LE(30) === 0x000a) {
        event.ioCtrlSequence = packet.readUInt32LE(32);
        event.ioCtrlCommand = packet.readUInt32LE(52);
      }
      const ioAck = parseAvIoCtrlAck(packet);
      if (ioAck) {
        const key = `${ioAck.ioCtrlSequence}`;
        const pending = active.ioCtrlAcks?.get(key);
        active.lastAvIoCtrlAck = { outerSequence: ioAck.outerSequence,
          ioCtrlSequence: ioAck.ioCtrlSequence, command: pending?.command ?? null,
          matchedPending: Boolean(pending), outerSequenceMatched: pending
            ? ioAck.outerSequence === pending.outerSequence : null };
        if (pending) {
          active.ioCtrlAcks.delete(key);
          clearTimeout(pending.timer);
          event.ackFor = `${ioAck.outerSequence}/${ioAck.ioCtrlSequence}`;
          event.ackOuterSequenceMatched = ioAck.outerSequence === pending.outerSequence;
          if (active.video) {
            active.video.acknowledgedControls ||= [];
            active.video.acknowledgedControls.push({ command: pending.command,
              ioCtrlSequence: ioAck.ioCtrlSequence, ackOuterSequence: ioAck.outerSequence,
              outerSequenceMatched: event.ackOuterSequenceMatched });
            if (active.video.acknowledgedControls.length > 16) active.video.acknowledgedControls.shift();
          }
          pending.resolve?.(ioAck);
        }
      }
      if (event.command === '0x0408' && packet.length >= 56 && packet[29] === 0x70
          && packet.readUInt16LE(30) === 0x000a) {
        const acknowledgement = buildAvIoCtrlReplyAck(active, packet);
        event.ackSent = { outerSequence: acknowledgement.sequence,
          ioCtrlSequence: packet.readUInt32LE(32) };
        sendSessionDatagram(active, acknowledgement.wire).catch(error => {
          event.ackError = error.message;
        });
      }
      if (event.command === '0x0428') {
        event.meaning = 'IOTC session setup/update';
        if (event.sessionIdMatch === true) {
          // FUN_00121fc0 actualiza el send-path con el endpoint del paquete 0x0428.
          const previousPort = active.port;
          active.port = remote.port;
          active.transportState = 'peer-route-observed';
          if (active.iotcReadyPending) {
            const pending = active.iotcReadyPending;
            active.iotcReadyPending = null;
            clearTimeout(pending.timer);
            pending.ready();
          }
          if (active.avPending && previousPort !== remote.port && !active.avPending.retried) {
            const pending = active.avPending;
            const retryPacket = decodeDatagram(pending.retryWire);
            if (retryPacket && retryPacket.length >= 8) {
              retryPacket.writeUInt16LE(active.sequence, 6);
              active.sequence = (active.sequence + 1) & 0xffff;
              const retryWire = encodeDatagram(retryPacket);
              retryPacket.fill(0);
              pending.retried = true;
              event.avRetryToPeerPort = remote.port;
              active.socket.send(retryWire, remote.port, active.ip, () => retryWire.fill(0));
            }
          }
        }
      }
      if (event.command === '0x0418') {
        event.meaning = 'IOTC session-close path';
        if (event.sessionIdMatch === true) {
          active.state = 'iotc-session-closed';
          active.transportState = 'closed';
          endVideo(active.video);
          if (active.iotcReadyPending) {
            const pending = active.iotcReadyPending;
            active.iotcReadyPending = null;
            clearTimeout(pending.timer);
            pending.failed(new Error(`La cámara cerró la sesión IOTC (0x0418) antes de habilitar AV; peer ${remote.address}:${remote.port}.`));
          }
          if (active.streamPending) {
            const pending = active.streamPending;
            active.streamPending = null;
            clearTimeout(pending.timer);
            pending.reject(new Error('La cámara cerró IOTC durante la consulta de modo de video.'));
          }
          if (active.avPending) {
            const pending = active.avPending;
            active.avPending = null;
            clearTimeout(pending.timer);
            pending.retryWire.fill(0);
            const routeEvents = active.events.filter(previous => previous.command === '0x0428')
              .slice(-2).map(describeTransportEvent).join('; ');
            const routeDetail = routeEvents ? ` Ruta observada: ${routeEvents}.` : '';
            pending.reject(new Error(`La cámara cerró la sesión IOTC (0x0418) antes de confirmar el inicio AV; ID correlacionado, peer ${remote.address}:${remote.port}.${routeDetail}`));
          }
        }
      }
      if (event.command === '0x0602' && packet.length >= 200) event.status = packet.readInt32LE(196);
      const avReply = parseAvLoginReply(packet);
      if (avReply) {
        event.avStatus = avReply.status;
        event.avMode = avReply.mode;
        if (active.avPending) {
          const pending = active.avPending;
          active.avPending = null;
          clearTimeout(pending.timer);
          pending.retryWire.fill(0);
          active.state = avReply.status === 0 ? 'av-login-accepted' : 'av-login-rejected';
          active.updatedAt = Date.now();
          touchSession(active);
          pending.resolve({ status: avReply.status, mode: avReply.mode });
        }
      }
      const streamReply = parseStreamControlReply(packet);
      if (streamReply) {
        event.streamStatus = streamReply.status;
        event.streamMode = streamReply.mode;
      }
      // El 803 vuelve por el socket UDP exclusivo de esta sesión, desde la IP
      // de la cámara. Su identificador AV no necesariamente es el token usado
      // por la pre-sesión LAN, por eso no se compara con active.token.
      if (streamReply && active.streamPending) {
        const pending = active.streamPending;
        active.streamPending = null;
        clearTimeout(pending.timer);
        // El número de secuencia IOTC continúa desde la respuesta 803. En la
        // captura funcional, 803 lleva seq=3 y el siguiente 255 sale con seq=4.
        active.sequence = (packet.readUInt16LE(6) + 1) & 0xffff;
        pending.resolve(streamReply);
      }
      active.events.push(event);
      if (active.events.length > 8) active.events.shift();
      active.updatedAt = Date.now();
    });
    socket.bind({ port: 0, address: nic.address }, () => {
      try { socket.setBroadcast(true); }
      catch (error) { finish(new Error(`No se pudo habilitar el broadcast LAN: ${error.message}`)); return; }
      const mode1 = buildSessionProbe(device.uid, token, 1);
      const sendMode1 = () => socket.send(mode1, LAN_SEARCH_PORT, broadcast, error => {
        if (error) finish(new Error(`No se pudo enviar la petición LAN modo 1 por broadcast a ${broadcast}:${LAN_SEARCH_PORT}: ${error.message}`));
      });
      // El cliente nativo mantiene AddLanSearchTask activo y vuelve a emitir
      // modo 1 cada 100 ms hasta recibir la respuesta o agotar el plazo.
      sendMode1();
      mode1Retry = setInterval(sendMode1, 100);
    });
  });
}

function startAvLogin(sessionId, account, password) {
  const active = sessions.get(sessionId);
  if (!active || Date.now() >= active.expiresAt) {
    return Promise.reject(new Error('La sesión LAN provisional caducó; vuelve a negociar.'));
  }
  if (active.state !== 'mode2-sent-awaiting-iotc-result') {
    if (active.state === 'iotc-session-closed') {
      return Promise.reject(new Error('La cámara ya cerró esta sesión IOTC (0x0418); vuelve a negociar una sesión nueva.'));
    }
    if (active.state === 'av-login-sent' && active.avPending) {
      return Promise.reject(new Error('Ya hay un inicio AV pendiente para esta sesión; espera su respuesta.'));
    }
    if (active.state === 'av-login-timeout') {
      return Promise.reject(new Error('El inicio AV anterior agotó el plazo; vuelve a negociar una sesión nueva.'));
    }
    if (active.state === 'av-login-accepted') {
      return Promise.reject(new Error('El inicio AV ya fue aceptado en esta sesión.'));
    }
    if (active.state === 'av-login-rejected') {
      return Promise.reject(new Error('La cámara rechazó el inicio AV de esta sesión. Vuelve a negociar antes de otro intento.'));
    }
    return Promise.reject(new Error(`La sesión IOTC está en estado «${active.state}» y no admite iniciar AV.`));
  }
  if (typeof account !== 'string' || typeof password !== 'string'
      || !account.trim() || Buffer.byteLength(account, 'utf8') > 256
      || Buffer.byteLength(password, 'utf8') > 256) {
    return Promise.reject(new Error('Cuenta y contraseña requeridas; máximo 256 bytes UTF-8 por campo.'));
  }
  const wire = buildAvLogin(account, password, active.token, active.sequence, 0);
  active.sequence = (active.sequence + 1) & 0xffff;
  active.state = 'av-login-sent';
  active.updatedAt = Date.now();

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (active.avPending?.timer !== timer) return;
      active.avPending.retryWire.fill(0);
      active.avPending = null;
      active.state = 'av-login-timeout';
      active.updatedAt = Date.now();
      const observed = active.events.slice(-6).map(describeTransportEvent).join('; ');
      const detail = observed ? ` Tráfico posterior: ${observed}.` : ' No se recibió tráfico posterior de la cámara.';
      const iotcControlSeen = active.events.some(event =>
        (event.command === '0x0428' || event.command === '0x0418') && event.sessionIdMatch === true);
      const next = iotcControlSeen
        ? ' La cámara procesó la ruta IOTC de esta sesión, pero no confirmó AV; revisa si el evento de cierre 0x0418 llegó antes de completar el login.'
        : '';
      reject(new Error(`Se envió el login AV, pero no llegó una respuesta 0x0408 en 5 s.${detail}${next}`));
    }, 5000);
    active.avPending = { timer, resolve, reject, retryWire: Buffer.from(wire), retried: false };
    active.socket.send(wire, active.port, active.ip, error => {
      wire.fill(0);
      if (!error) return;
      if (active.avPending?.timer === timer) {
        active.avPending.retryWire.fill(0);
        active.avPending = null;
      }
      clearTimeout(timer);
      active.state = 'av-login-send-error';
      active.updatedAt = Date.now();
      reject(new Error(`No se pudo enviar el login AV por UDP: ${error.message}`));
    });
  });
}

function publicSession(session) {
  return { sessionId: session.sessionId, ip: session.ip, port: session.port,
    state: session.state, transportState: session.transportState || 'unknown',
    expiresAt: session.expiresAt, events: session.events || [],
    lastAvIoCtrlAck: session.lastAvIoCtrlAck, video: videoSummary(session) };
}

function getLanSessionStatus(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() >= session.expiresAt) { closeSession(sessionId); return null; }
  return publicSession(session);
}

function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return;
  clearTimeout(session.expiryTimer);
  if (session.iotcReadyPending) {
    clearTimeout(session.iotcReadyPending.timer);
    session.iotcReadyPending.failed(new Error('La sesión se reemplazó por un reintento nuevo.'));
    session.iotcReadyPending = null;
  }
  if (session.avPending) {
    clearTimeout(session.avPending.timer);
    session.avPending.retryWire.fill(0);
    session.avPending.reject(new Error('La sesión LAN expiró durante el inicio AV.'));
    session.avPending = null;
  }
  if (session.streamPending) {
    clearTimeout(session.streamPending.timer);
    session.streamPending.reject(new Error('La sesión se reemplazó antes de recibir GETSTREAMCTRL_RESP.'));
    session.streamPending = null;
  }
  for (const pending of session.ioCtrlAcks?.values() || []) {
    clearTimeout(pending.timer);
    pending.reject(new Error('La sesión se cerró antes del acuse AVIOCTRL.'));
  }
  session.ioCtrlAcks?.clear();
  session.token?.fill(0);
  endVideo(session.video);
  sessions.delete(sessionId);
  try { session.socket.close(); } catch { /* ya estaba cerrado */ }
}

module.exports = { startLanNegotiation, startAvLogin, startAvVideo,
  setAvVideoQuality, probeAudioStartForVideo, closeSession, getLanSessionStatus, getLanVideoStatus,
  subscribeVideoFrames };
