import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import fs from 'fs';
import { Roles } from './roles.js';
import { logger } from './logger.js';

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: ['http://localhost:5173', 'http://localhost:3000'], credentials: true }
});

const PORT = process.env.PORT || 4000;
const ADMIN_SHARED_SECRET = process.env.ADMIN_SHARED_SECRET;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const DB_FILE = process.env.DB_FILE || './data/msnchat.db';

fs.mkdirSync('./data', { recursive: true });

// DB open
const db = await open({ filename: DB_FILE, driver: sqlite3.Database });
await db.exec('PRAGMA journal_mode = WAL');

// ---- Helpers ----
function truncateText(t) {
  if (!t) return "";
  return t.length > 80 ? t.substring(0, 80).replace(/\n/g, " ") + "..." : t.replace(/\n/g, " ");
}

// Presence and users
const presence = new Map(); // roomId -> Set(socketId)
const users = new Map(); // socketId -> { id, name, role, effectiveRole, afk, roomId, ip }
const userIndexById = new Map(); // userId -> socketId

async function loadRooms() {
  const rows = await db.all('SELECT * FROM rooms');
  for (const r of rows) if (!presence.has(r.id)) presence.set(r.id, new Set());
}
await loadRooms();

async function getPublicRoomInfo() {
  const rows = await db.all('SELECT id, name, description FROM rooms');
  return rows.map(r => ({
    id: r.id,
    name: r.name,
    description: r.description || '',
    occupants: (presence.get(r.id)?.size || 0)
  }));
}

function buildUserListForRoom(roomId) {
  const sockets = presence.get(roomId) || new Set();
  const list = [];
  for (const sid of sockets) {
    const u = users.get(sid);
    if (!u) continue;
    list.push({ id: u.id, name: u.name, role: u.effectiveRole || u.role, afk: u.afk });
  }
  return list;
}

const assertAdmin = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== Roles.ADMIN) return res.status(403).json({ error: 'Forbidden' });
    req.admin = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// --- Admin APIs ---
app.post('/api/admin/login', (req, res) => {
  const { sharedSecret, adminName } = req.body || {};
  if (!sharedSecret || sharedSecret !== ADMIN_SHARED_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = jwt.sign({ role: Roles.ADMIN, name: adminName || 'Admin' }, JWT_SECRET, { expiresIn: '12h' });
  logger.info(`Admin ${adminName || 'Admin'} logged in`);
  res.json({ token });
});

app.get('/api/rooms', async (req, res) => {
  res.json(await getPublicRoomInfo());
});

app.get('/api/admin/overview', assertAdmin, async (req, res) => {
  const rooms = await db.all('SELECT id, name, description, owner_user_id FROM rooms');
  const payload = [];
  for (const r of rooms) {
    const usersList = buildUserListForRoom(r.id);
    payload.push({
      id: r.id, name: r.name, description: r.description || '', ownerUserId: r.owner_user_id || null,
      occupants: usersList.length, users: usersList
    });
  }
  res.json(payload);
});

app.post('/api/admin/rooms/:roomId/owner', assertAdmin, async (req, res) => {
  const { roomId } = req.params;
  const { userId } = req.body || {};
  const room = await db.get('SELECT * FROM rooms WHERE id = ?', [roomId]);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  const socketId = userIndexById.get(userId);
  if (!socketId) return res.status(404).json({ error: 'User not found/online' });
  const u = users.get(socketId);
  if (!u || u.roomId !== roomId) return res.status(400).json({ error: 'User not in this room' });
  await db.run('UPDATE rooms SET owner_user_id = ? WHERE id = ?', [u.id, roomId]);
  for (const sid of presence.get(roomId) || []) {
    const usr = users.get(sid);
    if (!usr) continue;
    usr.effectiveRole = (usr.id === u.id) ? Roles.OWNER : usr.role;
  }
  io.to(roomId).emit('room:owner_updated', { roomId, ownerUserId: u.id });
  io.to(roomId).emit('room:user_list', buildUserListForRoom(roomId));
  logger.info(`Owner set: user ${u.name} (${u.id}) is now OWNER of room ${room.name}`);
  res.json({ ok: true, roomId, ownerUserId: u.id });
});

app.post('/api/admin/users/:userId/role', assertAdmin, async (req, res) => {
  const { userId } = req.params;
  const { role } = req.body || {};
  if (![Roles.MOD, Roles.GUIDE, Roles.SYSOP, Roles.ADMIN].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  const socketId = userIndexById.get(userId);
  if (!socketId) return res.status(404).json({ error: 'User not found/online' });
  const u = users.get(socketId);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const prev = u.role;
  u.role = role;
  const room = u.roomId ? await db.get('SELECT owner_user_id FROM rooms WHERE id = ?', [u.roomId]) : null;
  if (room && room.owner_user_id === u.id) u.effectiveRole = Roles.OWNER; else u.effectiveRole = role;
  if (u.roomId) io.to(u.roomId).emit('room:user_list', buildUserListForRoom(u.roomId));
  logger.info(`Role change: ${u.name} (${u.id}) ${prev} → ${role}`);
  res.json({ ok: true });
});

// Kick via admin
app.post('/api/admin/users/:userId/kick', assertAdmin, async (req, res) => {
  const { userId } = req.params;
  const socketId = userIndexById.get(userId);
  if (!socketId) return res.status(404).json({ error: 'User not online' });
  const u = users.get(socketId);
  if (!u || !u.roomId) return res.status(400).json({ error: 'User not in a room' });
  const rId = u.roomId;
  presence.get(rId)?.delete(socketId);
  io.sockets.sockets.get(socketId)?.leave(rId);
  users.get(socketId).roomId = null;
  io.to(rId).emit('room:user_list', buildUserListForRoom(rId));
  io.emit('rooms:update', await getPublicRoomInfo());
  io.to(socketId).emit('mod:kicked', { roomId: rId });
  logger.warn(`Kick: ${u.name} (${u.id}) from room ${rId}`);
  res.json({ ok: true });
});

// Ban via admin (by userId + IP)
app.post('/api/admin/users/:userId/ban', assertAdmin, async (req, res) => {
  const { userId } = req.params;
  const { minutes = 60, reason = '' } = req.body || {};
  const socketId = userIndexById.get(userId);
  let ip = null, name = null;
  if (socketId) {
    const u = users.get(socketId);
    ip = u?.ip || null;
    name = u?.name || '';
    if (u?.roomId) {
      presence.get(u.roomId)?.delete(socketId);
      io.sockets.sockets.get(socketId)?.leave(u.roomId);
      users.get(socketId).roomId = null;
      io.to(u.roomId).emit('room:user_list', buildUserListForRoom(u.roomId));
      io.emit('rooms:update', await getPublicRoomInfo());
      io.to(socketId).emit('mod:kicked', { roomId: u.roomId });
    }
  }
  const id = uuidv4();
  const now = Date.now();
  const exp = minutes ? now + minutes*60*1000 : null;
  await db.run('INSERT INTO bans (id, user_id, ip, reason, created_at, expires_at) VALUES (?,?,?,?,?,?)',
    [id, userId, ip, reason, now, exp]);
  logger.warn(`Ban: userId=${userId} ip=${ip||'n/a'} minutes=${minutes} reason="${reason}"`);
  res.json({ ok: true, id });
});

// Unban
app.post('/api/admin/users/:userId/unban', assertAdmin, async (req, res) => {
  const { userId } = req.params;
  await db.run('DELETE FROM bans WHERE user_id = ?', [userId]);
  logger.info(`Unban: userId=${userId}`);
  res.json({ ok: true });
});

// Mute (room-scoped)
app.post('/api/admin/users/:userId/mute', assertAdmin, async (req, res) => {
  const { userId } = req.params;
  const { roomId, minutes = 10, reason = '' } = req.body || {};
  if (!roomId) return res.status(400).json({ error: 'roomId required' });
  const id = uuidv4();
  const now = Date.now();
  const exp = minutes ? now + minutes*60*1000 : null;
  await db.run('INSERT INTO mutes (id, user_id, room_id, reason, created_at, expires_at) VALUES (?,?,?,?,?,?)',
    [id, userId, roomId, reason, now, exp]);
  logger.warn(`Mute: userId=${userId} roomId=${roomId} minutes=${minutes} reason="${reason}"`);
  res.json({ ok: true, id });
});

app.post('/api/admin/users/:userId/unmute', assertAdmin, async (req, res) => {
  const { userId } = req.params;
  const { roomId } = req.body || {};
  if (!roomId) return res.status(400).json({ error: 'roomId required' });
  await db.run('DELETE FROM mutes WHERE user_id = ? AND room_id = ?', [userId, roomId]);
  logger.info(`Unmute: userId=${userId} roomId=${roomId}`);
  res.json({ ok: true });
});

// --- Socket.IO ---
io.on('connection', async (socket) => {
  const ip = socket.handshake.address;
  // check ban by ip?
  const activeBanIp = await db.get('SELECT * FROM bans WHERE ip = ? AND (expires_at IS NULL OR expires_at > ?)', [ip, Date.now()]);
  if (activeBanIp) {
    socket.emit('error', { message: 'You are banned.' });
    socket.disconnect(true);
    return;
  }

  const user = {
    id: uuidv4(),
    name: `Anon-${String(Math.floor(Math.random()*100000)).padStart(5,'0')}`,
    role: Roles.USER,
    effectiveRole: Roles.USER,
    afk: false,
    roomId: null,
    ip
  };
  users.set(socket.id, user);
  userIndexById.set(user.id, socket.id);
  socket.emit('hello', { userId: user.id });

  logger.info(`Connect: ${user.name} (${user.id}) ip=${ip}`);

  // room create
  socket.on('room:create', async ({ name, description }) => {
    const trimmed = String(name||'').trim();
    if (!trimmed) return socket.emit('error', { message: 'Room name required' });
    const id = uuidv4();
    await db.run('INSERT INTO rooms (id, name, description, created_by, owner_user_id) VALUES (?,?,?,?,NULL)',
      [id, trimmed, String(description||'').trim(), user.id]);
    if (!presence.has(id)) presence.set(id, new Set());
    io.emit('rooms:update', await getPublicRoomInfo());
    logger.info(`Room created: ${trimmed} (${id}) by ${user.name}`);
  });

  socket.on('room:list', async () => {
    socket.emit('rooms:list', await getPublicRoomInfo());
  });

  socket.on('room:join', async ({ roomId, name }) => {
    const room = await db.get('SELECT * FROM rooms WHERE id = ?', [roomId]);
    if (!room) return socket.emit('error', { message: 'Room not found' });

    // check ban by userId
    const activeBan = await db.get('SELECT * FROM bans WHERE (user_id = ? OR ip = ?) AND (expires_at IS NULL OR expires_at > ?)',
      [user.id, user.ip, Date.now()]);
    if (activeBan) {
      socket.emit('error', { message: 'You are banned.' });
      return;
    }

    // leave previous
    if (user.roomId) {
      presence.get(user.roomId)?.delete(socket.id);
      socket.leave(user.roomId);
      io.to(user.roomId).emit('room:user_list', buildUserListForRoom(user.roomId));
      io.emit('rooms:update', await getPublicRoomInfo());
      logger.info(`Leave: ${user.name} left room ${user.roomId}`);
    }

    user.name = (String(name || '').trim()) || user.name;
    user.roomId = roomId;
    user.effectiveRole = (room.owner_user_id === user.id) ? Roles.OWNER : user.role;

    presence.get(roomId)?.add(socket.id);
    socket.join(roomId);

    socket.emit('room:joined', { roomId, users: buildUserListForRoom(roomId) });
    io.to(roomId).emit('room:user_list', buildUserListForRoom(roomId));
    io.emit('rooms:update', await getPublicRoomInfo());
    logger.info(`Join: ${user.name} joined room ${room.name}`);
  });

  socket.on('chat:message', async ({ text }) => {
    const t = String(text || '').slice(0, 2000);
    if (!t || !user.roomId) return;
    const room = await db.get('SELECT owner_user_id FROM rooms WHERE id = ?', [user.roomId]);
    if (!room) return;
    user.effectiveRole = (room.owner_user_id === user.id) ? Roles.OWNER : user.role;

    // mute check
    const muted = await db.get('SELECT * FROM mutes WHERE user_id = ? AND room_id = ? AND (expires_at IS NULL OR expires_at > ?)',
      [user.id, user.roomId, Date.now()]);
    if (muted) {
      socket.emit('error', { message: 'You are muted in this room.' });
      logger.info(`Muted message blocked from ${user.name} in room ${user.roomId}`);
      return;
    }

    const msg = {
      id: uuidv4(),
      from: { id: user.id, name: user.name, role: user.effectiveRole, afk: user.afk },
      text: t,
      ts: Date.now()
    };
    io.to(user.roomId).emit('chat:message', msg);

    await db.run('INSERT INTO messages (id, room_id, user_id, user_name, user_role, text, ts) VALUES (?,?,?,?,?,?,?)',
      [msg.id, user.roomId, user.id, user.name, user.effectiveRole, t, msg.ts]);
	  const preview = t.length > 80 ? t.substring(0, 80).replace(/\n/g, ' ') + '...' : t.replace(/\n/g, ' ');
	  logger.info(`Message: ${user.name} in room ${user.roomId}: ${preview}`);
  });

  socket.on('chat:pm', ({ toUserId, text }) => {
    const t = String(text || '').slice(0, 2000);
    if (!t) return;
    const targetSocketId = userIndexById.get(toUserId);
    if (!targetSocketId) return;
    const target = users.get(targetSocketId);
    if (!target) return;

    [socket.id, targetSocketId].forEach(sid => {
      io.to(sid).emit('chat:pm', {
        id: uuidv4(),
        from: { id: user.id, name: user.name },
        to: { id: target.id, name: target.name },
        text: t,
        ts: Date.now()
      });
    });
    const preview = truncateText(text);
	logger.info(`PM from ${user.name} to ${toUserId}: ${preview}`);

  });

  socket.on('user:afk', ({ afk }) => {
    user.afk = !!afk;
    if (user.roomId) io.to(user.roomId).emit('room:user_list', buildUserListForRoom(user.roomId));
    logger.info(`AFK: ${user.name} set AFK=${user.afk}`);
  });

  // client kick request (mods/owner/sysop/admin)
  socket.on('mod:kick', async ({ targetUserId }) => {
    if (!user.roomId) return;
    const room = await db.get('SELECT owner_user_id FROM rooms WHERE id = ?', [user.roomId]);
    if (!room) return;
    const effectiveRole = (room.owner_user_id === user.id) ? Roles.OWNER : user.role;
    const canKick = [Roles.MOD, Roles.OWNER, Roles.ADMIN, Roles.SYSOP].includes(effectiveRole);
    if (!canKick) return;
    const targetSocketId = userIndexById.get(targetUserId);
    if (!targetSocketId) return;
    const target = users.get(targetSocketId);
    if (!target || target.roomId !== user.roomId) return;

    presence.get(user.roomId)?.delete(targetSocketId);
    io.sockets.sockets.get(targetSocketId)?.leave(user.roomId);
    users.get(targetSocketId).roomId = null;

    io.to(user.roomId).emit('room:user_list', buildUserListForRoom(user.roomId));
    io.emit('rooms:update', await getPublicRoomInfo());
    io.to(targetSocketId).emit('mod:kicked', { roomId: user.roomId });
    logger.warn(`Kick: ${user.name} kicked ${target.name} from room ${user.roomId}`);
  });

  socket.on('disconnect', async () => {
    const u = users.get(socket.id);
    if (u?.roomId) {
      presence.get(u.roomId)?.delete(socket.id);
      io.to(u.roomId).emit('room:user_list', buildUserListForRoom(u.roomId));
      io.emit('rooms:update', await getPublicRoomInfo());
    }
    if (u) {
      logger.info(`Disconnect: ${u.name} (${u.id})`);
      userIndexById.delete(u.id);
    }
    users.delete(socket.id);
  });
});

server.listen(PORT, () => {
  logger.info(`MSN Chat clone server (SQLite) on http://localhost:${PORT}`);
});
