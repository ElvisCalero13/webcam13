'use strict';

// IOTC's unauthenticated local discovery. Only returns endpoint metadata;
// response payloads (which may contain identifiers) stay in memory and are discarded.
const dgram = require('node:dgram');
const os = require('node:os');
const { randomUUID } = require('node:crypto');
const { encodeDatagram, decodeDatagram } = require('./decode-pcap-video');

const discovered = new Map();
const DEVICE_TTL_MS = 5 * 60 * 1000;

function ipv4Number(ip) {
  return ip.split('.').reduce((value, part) => ((value << 8) | Number(part)) >>> 0, 0);
}

function numberIpv4(value) {
  return [24, 16, 8, 0].map(shift => (value >>> shift) & 0xff).join('.');
}

function findLanInterface() {
  const adapters = os.networkInterfaces();
  for (const [name, entries] of Object.entries(adapters)) {
    for (const entry of entries || []) {
      if (entry.family !== 'IPv4' || entry.internal || !entry.netmask) continue;
      const ip = ipv4Number(entry.address);
      const mask = ipv4Number(entry.netmask);
      const broadcast = numberIpv4((ip & mask) | (~mask >>> 0));
      return { name, address: entry.address, broadcast };
    }
  }
  throw new Error('No se encontró una interfaz IPv4 LAN activa.');
}

function buildSearchPacket(counter) {
  const count = counter & 0x0f;
  const continuation = count !== 0;
  const packet = Buffer.alloc(continuation ? 0x58 : 0x44);
  packet.writeUInt16LE(0x0204, 0);
  packet[2] = 0x14;
  packet.writeUInt16LE(continuation ? 0x48 : 0x34, 4);
  packet.writeUInt16LE(continuation ? 0x0603 : 0x0601, 8);
  packet.writeUInt16LE(0x0021, 10);
  packet[15] = 1;
  packet.writeUInt32LE(0x03010521, 0x34);
  if (continuation) packet.writeUInt32LE(count, 0x44);
  packet[3] |= 0x02;
  return encodeDatagram(packet);
}

function discoverCameras({ durationMs = 2000, port = 32761 } = {}) {
  if (!Number.isInteger(durationMs) || durationMs < 500 || durationMs > 5000) {
    return Promise.reject(new Error('La búsqueda debe durar entre 500 y 5000 ms.'));
  }
  const iface = findLanInterface();
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const found = new Map();
    let sent = 0;
    let finished = false;
    let timer;
    const finish = error => {
      if (finished) return;
      finished = true;
      clearInterval(timer);
      socket.close(() => error ? reject(error) : resolve({
        interface: iface.name,
        localIp: iface.address,
        broadcast: iface.broadcast,
        sent,
        devices: [...found.values()]
      }));
    };
    socket.on('error', error => finish(new Error(`Error UDP en ${iface.name}: ${error.message}`)));
    socket.on('message', (message, remote) => {
      const decoded = decodeDatagram(message);
      if (!decoded || decoded.length < 10) return;
      const type = decoded.readUInt16LE(2);
      const command = decoded.readUInt16LE(8);
      if (type !== 0x0217 || command !== 0x0602) return;
      const key = `${remote.address}:${remote.port}`;
      // Native handler passes the 0x0602 body at offset 16 to its UID matcher.
      // Keep the identifier server-side for a later session attempt; never return it.
      const uid = decoded.subarray(16, 36).toString('ascii').replace(/\0.*$/, '');
      const deviceId = found.get(key)?.deviceId || randomUUID();
      if (/^[A-Za-z0-9]{1,20}$/.test(uid)) {
        discovered.set(deviceId, { uid, ip: remote.address, port: remote.port, localIp: iface.address, seenAt: Date.now() });
        found.set(key, { deviceId, ip: remote.address, port: remote.port, response: '0x0217/0x0602', length: decoded.length });
      }
    });
    socket.bind({ port: 0, address: iface.address }, () => {
      try { socket.setBroadcast(true); }
      catch (error) { finish(error); return; }
      const send = () => {
        const packet = buildSearchPacket(sent & 0x0f);
        socket.send(packet, port, iface.broadcast, error => {
          if (error) finish(error);
        });
        sent++;
      };
      send();
      timer = setInterval(send, 50);
      setTimeout(() => finish(), durationMs);
    });
  });
}

function getDiscoveredDevice(deviceId) {
  const device = discovered.get(deviceId);
  if (!device) return null;
  if (Date.now() - device.seenAt > DEVICE_TTL_MS) {
    discovered.delete(deviceId);
    return null;
  }
  return { ...device };
}

module.exports = { discoverCameras, findLanInterface, getDiscoveredDevice };
