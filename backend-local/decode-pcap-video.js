#!/usr/bin/env node
'use strict';

// Decodifica la capa reversible de libIOTCAPIs, analiza fragmentos AV H.264
// de una captura PCAP y, solo si se pide con --out, escribe un elementary stream.
// Requiere Wireshark/tshark; no necesita dependencias npm.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const KEY = Buffer.from('Charlie is the designer of P2P!!', 'ascii');
const DEFAULT_TSHARK = 'C:\\Program Files\\Wireshark\\tshark.exe';

function usage() {
  console.log(`Uso:
  node .\\decode-pcap-video.js <captura.pcap|pcapng> [--camera IP] [--client IP]
  node .\\decode-pcap-video.js <captura.pcap|pcapng> --out <video.h264> [--camera IP] [--client IP]

Sin --out solo muestra estadísticas. Los valores IP por omisión corresponden
a la captura PCAPdroid analizada: cámara 192.168.100.26 y cliente 10.215.173.1.`);
}

function parseArgs(argv) {
  const result = { input: null, output: null, camera: '192.168.100.26', client: '10.215.173.1' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--out') result.output = argv[++i];
    else if (arg === '--camera') result.camera = argv[++i];
    else if (arg === '--client') result.client = argv[++i];
    else if (arg === '--help' || arg === '-h') result.help = true;
    else if (!result.input) result.input = arg;
    else throw new Error(`Argumento no reconocido: ${arg}`);
  }
  return result;
}

function rotateLeft(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

// Inversa de FUN_0010b4bc para el rango solicitado. Bytes posteriores al
// límite se copian intactos, como hace la rutina nativa.
function inverseTransform(input, requestedLimit) {
  const output = Buffer.from(input);
  const limit = Math.min(input.length, requestedLimit);
  let offset = 0;

  for (; offset + 16 <= limit; offset += 16) {
    const x0 = input.readUInt32LE(offset);
    const x1 = input.readUInt32LE(offset + 4);
    const x2 = input.readUInt32LE(offset + 8);
    const x3 = input.readUInt32LE(offset + 12);
    const mixed = Buffer.alloc(16);
    mixed.writeUInt32LE(rotateLeft(x0, 3), 0);
    mixed.writeUInt32LE(rotateLeft(x1, 7), 4);
    mixed.writeUInt32LE(rotateLeft(x2, 11), 8);

    const v3 = (((mixed[5] << 16) | (mixed[0] << 24) | mixed[2] | (mixed[1] << 8)) ^ 0x74207369) >>> 0;
    const v4Parts = (
      (((x3 >>> 17) & 0xff) << 16)
      | ((((x3 & 0x1ffff) >>> 1) << 24) >>> 0)
      | ((((x3 >>> 17) | (x3 << 15)) >>> 8) & 0xff)
      | (mixed[10] << 8)
    ) >>> 0;
    const v4 = (v4Parts ^ 0x2065696c) >>> 0;
    const v5 = (((mixed[7] << 16) | (mixed[3] << 24) | mixed[6] | (mixed[4] << 8)) ^ 0x64206568) >>> 0;
    const v0Parts = (((x3 << 15) & 0xff000000) | (mixed[8] << 16) | mixed[11] | (mixed[9] << 8)) >>> 0;
    const v0 = (((x3 & 0x1ffff) >>> 16) | (((v0Parts ^ 0x72616843) << 1) >>> 0)) >>> 0;

    output.writeUInt32LE(v0, offset);
    output.writeUInt32LE(rotateLeft(v4, 5), offset + 4);
    output.writeUInt32LE(rotateLeft(v3, 9), offset + 8);
    output.writeUInt32LE(rotateLeft(v5, 13), offset + 12);
  }

  const remainder = limit - offset;
  if (remainder > 0) {
    let tail = Buffer.from(input.subarray(offset, limit));
    if (remainder === 2) tail = Buffer.from([tail[1], tail[0]]);
    else if (remainder === 4) tail = Buffer.from([tail[2], tail[3], tail[0], tail[1]]);
    else if (remainder === 8) tail = Buffer.from([tail[7], tail[4], tail[3], tail[2], tail[1], tail[6], tail[5], tail[0]]);
    else if (remainder === 16) tail = Buffer.from([tail[11], tail[9], tail[8], tail[15], tail[13], tail[10], tail[12], tail[14], tail[2], tail[1], tail[5], tail[0], tail[6], tail[4], tail[7], tail[3]]);
    for (let i = 0; i < remainder; i++) output[offset + i] = KEY[i] ^ tail[i];
  }
  return output;
}

// FUN_0010e670, dirección nativa de codificación. Esta es una mezcla reversible
// de bytes, no una primitiva criptográfica.
function forwardTransform(input, requestedLimit) {
  const output = Buffer.from(input);
  const limit = Math.min(input.length, requestedLimit);
  let offset = 0;
  for (; offset + 16 <= limit; offset += 16) {
    const a = input.readUInt32LE(offset);
    const b = input.readUInt32LE(offset + 4);
    const c = input.readUInt32LE(offset + 8);
    const d = input.readUInt32LE(offset + 12);
    const x = ((a >>> 1 | a << 31) ^ 0x72616843) >>> 0;
    const y = ((b >>> 5 | b << 27) ^ 0x2065696c) >>> 0;
    const z = ((c >>> 9 | c << 23) ^ 0x74207369) >>> 0;
    const w = ((d >>> 13 | d << 19) ^ 0x64206568) >>> 0;
    const q = ((((y >>> 8) & 0xff) << 16) | (x << 24) | ((x >>> 16) & 0xff) | (x & 0xff00)) >>> 0;
    const r = (((x & 0xff000000) | ((y >>> 24) << 16) | ((y >>> 16) & 0xff) | ((y & 0xff) << 8))) >>> 0;
    const o0 = (((((w & 0xff000000) | ((z & 0xff) << 16) | (z >>> 24) | (z & 0xff00)) >>> 3) | ((z >>> 24) << 29))) >>> 0;
    const o1bits = (((w & 0xff) << 16) | ((w >>> 16) << 24) | ((w >>> 8) & 0xff) | (((z >>> 16) & 0xff) << 8)) >>> 0;
    const o1 = ((o1bits >>> 7) | ((w >>> 8) << 25)) >>> 0;
    output.writeUInt32LE(o0, offset);
    output.writeUInt32LE(o1, offset + 4);
    output.writeUInt32LE((q >>> 11 | q << 21) >>> 0, offset + 8);
    output.writeUInt32LE((r >>> 15 | r << 17) >>> 0, offset + 12);
  }

  const remainder = limit - offset;
  if (remainder > 0) {
    const tail = Buffer.alloc(remainder);
    for (let i = 0; i < remainder; i++) tail[i] = KEY[i] ^ input[offset + i];
    let permuted = tail;
    if (remainder === 2) permuted = Buffer.from([tail[1], tail[0]]);
    else if (remainder === 4) permuted = Buffer.from([tail[2], tail[3], tail[0], tail[1]]);
    else if (remainder === 8) permuted = Buffer.from([tail[7], tail[4], tail[3], tail[2], tail[1], tail[6], tail[5], tail[0]]);
    else if (remainder === 16) permuted = Buffer.from([tail[11], tail[9], tail[8], tail[15], tail[13], tail[10], tail[12], tail[14], tail[2], tail[1], tail[5], tail[0], tail[6], tail[4], tail[7], tail[3]]);
    permuted.copy(output, offset);
  }
  return output;
}

function decodeDatagram(raw) {
  if (raw.length < 16) return null;
  const header = inverseTransform(raw.subarray(0, 16), 16);
  const rest = raw.subarray(16);
  const transformedLength = (header[3] & 1) ? 48 : rest.length;
  return Buffer.concat([header, inverseTransform(rest, transformedLength)]);
}

function encodeDatagram(decoded) {
  if (decoded.length < 16) throw new Error('El datagrama IOTC debe contener al menos 16 bytes.');
  const limit = decoded[3] & 1 ? 64 : decoded.length;
  return forwardTransform(decoded, limit);
}

function startsWithAnnexB(data) {
  if (data.length >= 5 && data[0] === 0 && data[1] === 0 && data[2] === 0 && data[3] === 1) {
    return { prefixLength: 4, nalType: data[4] & 0x1f };
  }
  if (data.length >= 4 && data[0] === 0 && data[1] === 0 && data[2] === 1) {
    return { prefixLength: 3, nalType: data[3] & 0x1f };
  }
  return null;
}

function percentile(sorted, ratio) {
  return sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * ratio))] : 0;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help || !options.input) { usage(); return options.help ? 0 : 2; }

  const inputPath = path.resolve(options.input);
  if (!fs.existsSync(inputPath)) throw new Error(`No existe la captura: ${inputPath}`);
  const tshark = process.env.TSHARK_PATH || (fs.existsSync(DEFAULT_TSHARK) ? DEFAULT_TSHARK : 'tshark');
  const filter = `ip.src==${options.camera} && ip.dst==${options.client} && udp`;
  const capture = spawnSync(tshark, ['-r', inputPath, '-Y', filter, '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_relative', '-e', 'udp.payload'], {
    encoding: 'utf8', windowsHide: true, maxBuffer: 128 * 1024 * 1024,
  });
  if (capture.error) throw capture.error;
  if (capture.status !== 0) throw new Error(capture.stderr || `tshark terminó con código ${capture.status}`);

  const allFrames = new Map();
  let datagrams = 0;
  let avVideoFragments = 0;
  let auxiliaryFragments = 0;
  let malformed = 0;

  for (const line of capture.stdout.split(/\r?\n/)) {
    if (!line) continue;
    const [packetNumber, relativeTime, payloadHex] = line.split('\t');
    if (!payloadHex) continue;
    const raw = Buffer.from(payloadHex.replaceAll(':', ''), 'hex');
    const packet = decodeDatagram(raw);
    datagrams++;
    if (!packet || packet.length < 52 || packet[0] !== 0x04 || packet[1] !== 0x02) continue;

    // IOTC payload begins at UDP offset 28. AV subtype 3 carries frame data.
    if (packet[28] !== 1 || packet[29] !== 3) continue;
    const frameNo = packet.readUInt32LE(32);
    const timestamp = packet.readUInt32LE(36);
    const index = packet.readUInt16LE(40);
    const flags = packet.readUInt16LE(42);
    const dataLength = packet.readUInt16LE(44);
    if (52 + dataLength > packet.length) { malformed++; continue; }
    const data = Buffer.from(packet.subarray(52, 52 + dataLength));
    const firstNal = index === 0 ? startsWithAnnexB(data) : null;

    if (flags === 0x18 && dataLength === 424) auxiliaryFragments++;
    if (flags === 0x10) avVideoFragments++;

    let frame = allFrames.get(frameNo);
    if (!frame) {
      frame = { frameNo, timestamp, firstTime: Number(relativeTime), parts: new Map(), flags, firstNal };
      allFrames.set(frameNo, frame);
    }
    frame.parts.set(index, data);
  }

  const videoFrames = [];
  let framesWithIndexGaps = 0;
  for (const frame of allFrames.values()) {
    const zero = frame.parts.get(0);
    const nal = zero && startsWithAnnexB(zero);
    if (!nal || ![1, 5, 7, 8].includes(nal.nalType)) continue;

    const indexes = [...frame.parts.keys()].sort((a, b) => a - b);
    const contiguous = indexes.every((value, position) => value === position);
    if (!contiguous) framesWithIndexGaps++;
    const lastIndex = indexes[indexes.length - 1];
    const size = lastIndex * 1024 + frame.parts.get(lastIndex).length;
    const bytes = Buffer.alloc(size);
    for (const [index, part] of frame.parts) part.copy(bytes, index * 1024);
    videoFrames.push({ ...frame, bytes, size, segments: indexes.length, nalType: nal.nalType, contiguous });
  }
  videoFrames.sort((a, b) => a.frameNo - b.frameNo);

  const sizes = videoFrames.map(frame => frame.size).sort((a, b) => a - b);
  const totalBytes = videoFrames.reduce((sum, frame) => sum + frame.size, 0);
  console.log(`Captura: ${inputPath}`);
  console.log(`Datagramas cámara→cliente revisados: ${datagrams}`);
  console.log(`Fragmentos AV subtipo 3 con flags 0x10: ${avVideoFragments}`);
  console.log(`Paquetes auxiliares flags 0x18 / 424 bytes: ${auxiliaryFragments}`);
  console.log(`Unidades H.264 Annex B recuperadas: ${videoFrames.length}`);
  console.log(`Fragmentos con huecos de índice: ${framesWithIndexGaps}; paquetes malformados: ${malformed}`);
  console.log(`Bytes H.264 reensamblados: ${totalBytes}; tamaño medio: ${Math.round(totalBytes / Math.max(1, videoFrames.length))}; p95: ${percentile(sizes, 0.95)}; máximo: ${sizes.at(-1) || 0}`);

  if (options.output) {
    const outputPath = path.resolve(options.output);
    fs.writeFileSync(outputPath, Buffer.concat(videoFrames.filter(frame => frame.contiguous).map(frame => frame.bytes)));
    console.log(`Elementary stream escrito en: ${outputPath}`);
  } else {
    console.log('No se escribió ningún video. Agrega --out <archivo.h264> para exportar el flujo H.264.');
  }
  console.log('Nota: los huecos de índice se detectan; una captura truncada al final de un cuadro puede no ser detectable.');
  return 0;
}

module.exports = { inverseTransform, forwardTransform, decodeDatagram, encodeDatagram };

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
