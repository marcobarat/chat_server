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
import argon2 from 'argon2';
import { logger } from './logger.js';
import multer from 'multer';
import path from 'path';

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('./uploads'));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: ['http://localhost:5173','http://localhost:3000'], credentials: true },
  pingInterval: 25000, pingTimeout: 20000, perMessageDeflate: false, maxHttpBufferSize: 1_000_000
});

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const DB_FILE = process.env.DB_FILE || './data/berrychat.db';

fs.mkdirSync('./data', { recursive: true });
const db = await open({ filename: DB_FILE, driver: sqlite3.Database });
await db.exec('PRAGMA journal_mode = WAL');
try {
  await db.exec('ALTER TABLE rooms ADD COLUMN owner_password TEXT');
} catch {}

const UPLOAD_DIR = './uploads'; fs.mkdirSync(UPLOAD_DIR,{recursive:true});
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname||''))
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = ['image/png','image/jpeg','image/webp','image/gif'].includes(file.mimetype);
    cb(ok ? null : new Error('Invalid type'));
  }
});

const presence = new Map();
const sockets  = new Map();
const ROLE_RANK = { admin:6, sysop:5, guide:4, owner:3, mod:2, user:1 };
const rankOf = r => ROLE_RANK[r] || 1;
const randomRoomPassword = () => Array.from({length:8},()=>Math.floor(Math.random()*10)).join('');
const userEffectiveRole = (g, rr) => [g||'user', rr||'user'].sort((a,b)=>rankOf(b)-rankOf(a))[0];
const ensurePresence = id => (presence.has(id)||presence.set(id,new Set()), presence.get(id));
const sortUsers = a => a.sort((x,y)=> (rankOf(y.role)-rankOf(x.role)) || x.name.localeCompare(y.name));
async function buildUserList(roomId){
  const set = presence.get(roomId)||new Set(); const arr=[];
  for(const sid of set){ const s=sockets.get(sid); if(!s) continue; arr.push({id:s.userId,name:s.username,role:s.effectiveRole,afk:s.afk}); }
  return sortUsers(arr);
}
async function getRoomRole(roomId,userId){ const rr=await db.get('SELECT role FROM room_roles WHERE room_id=? AND user_id=?',[roomId,userId]); return rr?.role||'user'; }
function srecOrExit(socket, event){ const s=sockets.get(socket.id); if(!s){ logger.warn(`Stale ${event} on ${socket.id}`); return null; } return s; }

// ---------- HEALTH ----------
app.get('/api/health', (_req,res)=>res.json({ok:true, ts:Date.now()}));

// ---------- UPLOAD ----------
app.post('/api/upload', upload.single('image'), (req,res)=>{
  try{
    const auth=req.headers.authorization||''; const tk=auth.startsWith('Bearer ')?auth.slice(7):null;
    if(!tk) return res.status(401).json({error:'Missing token'});
    jwt.verify(tk, JWT_SECRET);
    const url = `/uploads/${req.file.filename}`;
    res.json({ url });
  }catch(e){ res.status(401).json({error:'Unauthorized'}); }
});

// ---------- AUTH ----------
app.post('/api/auth/register', async (req,res)=>{
  try{
    const { username, password, confirm, gender } = req.body||{};
    if(!username||!password||!confirm) return res.status(400).json({error:'Missing fields'});
    if(password!==confirm) return res.status(400).json({error:'Passwords do not match'});
    const exists = await db.get('SELECT id FROM users WHERE username=?',[username]);
    if(exists) return res.status(409).json({error:'Username already exists'});
    const pass_hash = await argon2.hash(password, { type: argon2.argon2id, memoryCost:19456, timeCost:2, parallelism:1 });
    const id = uuidv4(); const g = ['M','F','O'].includes((gender||'O').toUpperCase())?(gender||'O').toUpperCase():'O';
    await db.run('INSERT INTO users (id, username, pass_hash, gender, global_role, created_at) VALUES (?,?,?,?,?,?)',
      [id, username, pass_hash, g, 'user', Date.now()]);
    const token = jwt.sign({ userId:id, username, gender:g, globalRole:'user' }, JWT_SECRET, { expiresIn:'24h' });
    res.json({ token });
  }catch(e){ res.status(500).json({error:'Server error'}); }
});

app.post('/api/auth/login', async (req,res)=>{
  try{
    const { username, password } = req.body||{};
    const u = await db.get('SELECT * FROM users WHERE username=?',[username]);
    if(!u) return res.status(401).json({error:'Invalid credentials'});
    const ok = await argon2.verify(u.pass_hash, password);
    if(!ok) return res.status(401).json({error:'Invalid credentials'});
    const token = jwt.sign({ userId:u.id, username:u.username, gender:u.gender, globalRole:u.global_role }, JWT_SECRET, { expiresIn:'24h' });
    res.json({ token });
  }catch(e){ res.status(500).json({error:'Server error'}); }
});

app.post('/api/user/change-password', async (req,res)=>{
  try{
    const auth=req.headers.authorization||''; const tk=auth.startsWith('Bearer ')?auth.slice(7):null;
    if(!tk) return res.status(401).json({error:'Missing token'});
    const payload = jwt.verify(tk, JWT_SECRET);
    const { oldPass, newPass, confirm } = req.body||{};
    if(!newPass||newPass!==confirm) return res.status(400).json({error:'Passwords do not match'});
    const u = await db.get('SELECT * FROM users WHERE id=?',[payload.userId]);
    const ok = await argon2.verify(u.pass_hash, oldPass||''); if(!ok) return res.status(401).json({error:'Invalid password'});
    const pass_hash = await argon2.hash(newPass, { type: argon2.argon2id, memoryCost:19456, timeCost:2, parallelism:1 });
    await db.run('UPDATE users SET pass_hash=? WHERE id=?',[pass_hash,u.id]);
    res.json({ ok:true });
  }catch(e){ res.status(500).json({error:'Server error'}); }
});

// ---------- ADMIN ----------
function assertAdmin(req,res,next){
  const auth=req.headers.authorization||''; const tk=auth.startsWith('Bearer ')?auth.slice(7):null;
  if(!tk) return res.status(401).json({error:'Missing token'});
  try{
    const p=jwt.verify(tk,JWT_SECRET);
    db.get('SELECT global_role FROM users WHERE id=?',[p.userId]).then(r=>{
      if(!r) return res.status(401).json({error:'Invalid user'});
      if(r.global_role!=='admin') return res.status(403).json({error:'Forbidden'});
      req.user={...p,globalRole:r.global_role}; next();
    });
  }catch{ return res.status(401).json({error:'Invalid token'}); }
}

app.get('/api/admin/users', assertAdmin, async (_req,res)=>{
  res.json(await db.all('SELECT id,username,gender,global_role,created_at FROM users ORDER BY created_at DESC'));
});
app.post('/api/admin/users/:userId/global-role', assertAdmin, async (req,res)=>{
  const { userId } = req.params; const { role } = req.body||{};
  if(!['user','mod','guide','sysop','admin'].includes(role)) return res.status(400).json({error:'Invalid role'});
  await db.run('UPDATE users SET global_role=? WHERE id=?',[role,userId]);
  res.json({ ok:true });
});

app.get('/api/rooms', async (_req,res)=>{
  const rows = await db.all('SELECT id,name,description FROM rooms ORDER BY created_at DESC');
  res.json(rows.map(r=>({id:r.id,name:r.name,description:r.description||'',occupants:(presence.get(r.id)?.size||0)})));
});

app.get('/api/rooms/resolve', async (req,res)=>{
  const q=String(req.query.q||'').trim(); if(!q) return res.status(400).json({error:'Missing q'});
  const r = await db.get('SELECT id,name FROM rooms WHERE id=? OR name=?',[q,q]);
  if(!r) return res.status(404).json({error:'Not found'}); res.json(r);
});

// ---------- SOCKET AUTH ----------
io.use(async (socket,next)=>{
  try{
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    if(!token) return next(new Error('Missing token'));
    const p = jwt.verify(token, JWT_SECRET);
    const u = await db.get('SELECT id,username,gender,global_role FROM users WHERE id=?',[p.userId]);
    if(!u) return next(new Error('Invalid user'));
    socket.data.user=u; next();
  }catch{ next(new Error('Auth error')); }
});

const ROLE_RANK_MAP = { admin:6, sysop:5, guide:4, owner:3, mod:2, user:1 };
const rankOfRole = r => ROLE_RANK_MAP[r] || 1;

// ---------- SOCKET EVENTS ----------
io.on('connection', async (socket)=>{
  const u = socket.data.user;
  sockets.set(socket.id, { userId:u.id, username:u.username, gender:u.gender, globalRole:u.global_role,
    effectiveRole:u.global_role, roomId:null, afk:false, blocked:new Set(), msgBurst:{count:0,ts:Date.now()} });

  // admin live feeds
  if(u.global_role==='admin'){
    socket.join('__admin');
    const rows = await db.all('SELECT id,name,description FROM rooms ORDER BY created_at DESC');
    socket.emit('admin:rooms', rows.map(r=>({id:r.id,name:r.name,description:r.description||'',occupants:(presence.get(r.id)?.size||0)})));
    socket.emit('admin:users', await db.all('SELECT id,username,gender,global_role,created_at FROM users ORDER BY created_at DESC'));
  }

  socket.emit('hello',{ userId:u.id, username:u.username, globalRole:u.global_role });

  // CREATE
  socket.on('room:create', async ({name,description})=>{
    const srec=srecOrExit(socket,'room:create'); if(!srec) return;
    const trimmed=String(name||'').trim(); if(!trimmed) return socket.emit('error',{message:'Room name required'});
    const id=uuidv4(); const plain=randomRoomPassword(); const hash=await argon2.hash(plain,{type:argon2.argon2id});
    await db.run('INSERT INTO rooms (id,name,description,owner_password,owner_password_hash,created_by,created_at) VALUES (?,?,?,?,?,?,?)',
      [id,trimmed,String(description||'').trim(),plain,hash,srec.userId,Date.now()]);
    await db.run('INSERT INTO room_roles (room_id,user_id,role) VALUES (?,?,?)',[id,srec.userId,'owner']);
    if(srec.roomId){ presence.get(srec.roomId)?.delete(socket.id); socket.leave(srec.roomId); }
    ensurePresence(id).add(socket.id);
    srec.roomId=id; srec.effectiveRole=userEffectiveRole(srec.globalRole,'owner');
    socket.join(id);

    // update lists
    const rows=await db.all('SELECT id,name,description FROM rooms ORDER BY created_at DESC');
    const mapped=rows.map(r=>({id:r.id,name:r.name,description:r.description||'',occupants:(presence.get(r.id)?.size||0)}));
    io.emit('rooms:update',mapped); io.to('__admin').emit('admin:rooms',mapped);

    socket.emit('room:owner_password',{roomId:id,password:plain});
    socket.emit('room:joined',{roomId:id,users:await buildUserList(id),you:{id:srec.userId,name:srec.username,role:srec.effectiveRole}});
    // history (empty)
    socket.emit('chat:history', []);
  });

  // LIST
  socket.on('room:list', async ()=>{
    const rows=await db.all('SELECT id,name,description FROM rooms ORDER BY created_at DESC');
    socket.emit('rooms:list', rows.map(r=>({id:r.id,name:r.name,description:r.description||'',occupants:(presence.get(r.id)?.size||0)})));
  });

  // JOIN
  socket.on('room:join', async ({roomId,roomName,createIfMissing})=>{
    const srec=srecOrExit(socket,'room:join'); if(!srec) return;
    let room=null;
    if(roomId){ room=await db.get('SELECT * FROM rooms WHERE id=?',[roomId]); }
    else if(roomName){ room=await db.get('SELECT * FROM rooms WHERE name=?',[roomName]); }
    if(!room && createIfMissing){
      const id=uuidv4(); const plain=randomRoomPassword(); const hash=await argon2.hash(plain,{type:argon2.argon2id});
      await db.run('INSERT INTO rooms (id,name,description,owner_password,owner_password_hash,created_by,created_at) VALUES (?,?,?,?,?,?,?)',[id,roomName,'',plain,hash,srec.userId,Date.now()]);
      await db.run('INSERT INTO room_roles (room_id,user_id,role) VALUES (?,?,?)',[id,srec.userId,'owner']);
      room=await db.get('SELECT * FROM rooms WHERE id=?',[id]);
      socket.emit('room:owner_password',{roomId:id,password:plain});
    }
    if(!room) return socket.emit('error',{message:'Room not found'});

    // ban check
    const ban = await db.get('SELECT * FROM room_bans WHERE room_id=? AND user_id=?',[room.id,u.id]);
    if(ban){ if(!ban.until_ts || ban.until_ts > Date.now()){ return socket.emit('error',{message:'Sei bannato da questa stanza'}); } else { await db.run('DELETE FROM room_bans WHERE room_id=? AND user_id=?',[room.id,u.id]); } }

    if(srec.roomId){ presence.get(srec.roomId)?.delete(socket.id); socket.leave(srec.roomId); }
    srec.roomId=room.id; srec.effectiveRole=userEffectiveRole(srec.globalRole, await getRoomRole(room.id,u.id));
    ensurePresence(room.id).add(socket.id); socket.join(room.id);
    socket.emit('room:joined',{roomId:room.id,users:await buildUserList(room.id),you:{id:u.id,name:u.username,role:srec.effectiveRole}});

    // send last 50 messages history
    const hist = await db.all('SELECT id,user_name as fromName,user_role as fromRole,text,kind,ts FROM messages WHERE room_id=? ORDER BY ts DESC LIMIT 50', [room.id]);
    socket.emit('chat:history', hist.reverse().map(m => (m.kind==='chat'? { id:m.id, from:{ name:m.fromName||'system', role:m.fromRole||'user' }, text:m.text, ts:m.ts } : { id:m.id, system:true, text:m.text, kind:m.kind, ts:m.ts })));

    if(rankOfRole(srec.effectiveRole) >= rankOfRole('owner') && room.owner_password){
      socket.emit('room:owner_password',{roomId:room.id,password:room.owner_password});
    }

    // broadcast join
    const txt=`${u.username} è entrato nella stanza`;
    io.to(room.id).emit('chat:system',{ text:txt, kind:'info', ts:Date.now() });
    io.to(room.id).emit('room:user_list', await buildUserList(room.id));

  });

  // LEFT
  socket.on('room:disconnection', async ({roomId,roomName})=>{
    const srec=srecOrExit(socket,'room:left'); if(!srec) return;
    let room=null;
    if(roomId){ room=await db.get('SELECT * FROM rooms WHERE id=?',[roomId]); }
    else if(roomName){ room=await db.get('SELECT * FROM rooms WHERE name=?',[roomName]); }

    // broadcast left
    const txt=`${u.username} è uscito dalla stanza`;
    io.to(room.id).emit('chat:system',{ text:txt, kind:'info', ts:Date.now() });
    io.to(roomId).emit('room:user_list', await buildUserList(roomId));
  });
  // OWNER CLAIM
  socket.on('room:owner_claim', async ({roomId,password})=>{
    const srec=srecOrExit(socket,'room:owner_claim'); if(!srec) return;
    const r=await db.get('SELECT owner_password_hash,owner_password,name FROM rooms WHERE id=?',[roomId]);
    if(!r) return socket.emit('error',{message:'Room not found'});
    const ok=await argon2.verify(r.owner_password_hash, String(password||'')); if(!ok) return socket.emit('error',{message:'Password errata'});
    await db.run('INSERT OR REPLACE INTO room_roles (room_id,user_id,role) VALUES (?,?,?)',[roomId,u.id,'owner']);
    srec.effectiveRole=userEffectiveRole(srec.globalRole,'owner');
    socket.emit('room:owner_password',{roomId,password:r.owner_password});
    io.to(roomId).emit('room:user_list', await buildUserList(roomId));
  });

  // BROADCAST
  socket.on('chat:broadcast', async ({text})=>{
    const srec=srecOrExit(socket,'chat:broadcast'); if(!srec||!srec.roomId) return;
    if(!['admin','sysop','guide'].includes(srec.effectiveRole)) return;
    const msg=String(text||'').slice(0,1500); if(!msg) return;
    io.to(srec.roomId).emit('chat:system',{text:msg,kind:'broadcast',ts:Date.now()});
    await db.run('INSERT INTO messages (id,room_id,user_id,user_name,user_role,kind,text,ts) VALUES (?,?,?,?,?,?,?,?)',
      [uuidv4(),srec.roomId,u.id,u.username,srec.effectiveRole,'broadcast',msg,Date.now()]);
  });

  // MESSAGE (rate-limit 5/2s)
  socket.on('chat:message', async ({text})=>{
    const srec=srecOrExit(socket,'chat:message'); if(!srec||!srec.roomId) return;
    const now=Date.now(); if(now - srec.msgBurst.ts > 2000){ srec.msgBurst={count:0,ts:now}; }
    if(++srec.msgBurst.count>5) return;
    const msg=String(text||'').slice(0,4000); if(!msg) return;
    const set=presence.get(srec.roomId)||new Set();
    for(const sid of set){ const rcv=sockets.get(sid); if(!rcv) continue; if(rcv.blocked?.has?.(srec.userId)) continue;
      io.to(sid).emit('chat:message',{ id:uuidv4(), from:{id:srec.userId,name:srec.username,role:srec.effectiveRole,afk:srec.afk}, text:msg, ts:now }); }
    await db.run('INSERT INTO messages (id,room_id,user_id,user_name,user_role,kind,text,ts) VALUES (?,?,?,?,?,?,?,?)',
      [uuidv4(),srec.roomId,srec.userId,srec.username,srec.effectiveRole,'chat',msg,now]);
  });

  // TYPING
  socket.on('chat:typing', () => {
    const srec = srecOrExit(socket,'chat:typing'); if(!srec||!srec.roomId) return;
    io.to(srec.roomId).emit('chat:typing', { userId: srec.userId, name: srec.username, ts: Date.now() });
  });

  // PM
  socket.on('chat:pm', ({toUserId,text})=>{
    const srec=srecOrExit(socket,'chat:pm'); if(!srec) return;
    const t=String(text||'').slice(0,4000); if(!t||!toUserId) return;
    let targetSid=null; for(const [sid,rec] of sockets.entries()) if(rec.userId===toUserId){ targetSid=sid; break; }
    if(!targetSid) return;
    [socket.id,targetSid].forEach(sid=> io.to(sid).emit('chat:pm',{ id:uuidv4(), from:{id:srec.userId,name:srec.username}, to:{id:toUserId}, text:t, ts:Date.now() }) );
  });

  // BLOCK/UNBLOCK
  socket.on('user:block', ({userId})=>{ const srec=srecOrExit(socket,'user:block'); if(!srec||!userId) return; srec.blocked.add(userId); socket.emit('user:blocklist',Array.from(srec.blocked)); });
  socket.on('user:unblock', ({userId})=>{ const srec=srecOrExit(socket,'user:unblock'); if(!srec||!userId) return; srec.blocked.delete(userId); socket.emit('user:blocklist',Array.from(srec.blocked)); });

  // AFK
  socket.on('user:afk', async ({afk})=>{
    const srec=srecOrExit(socket,'user:afk'); if(!srec) return; srec.afk=!!afk;
    if(srec.roomId){ io.to(srec.roomId).emit('room:user_list', await buildUserList(srec.roomId));
      const txt=srec.afk?`${srec.username} si è assentato`:`${srec.username} è tornato`;
      io.to(srec.roomId).emit('chat:system',{ text:txt, kind:'info', ts:Date.now() });
    }
  });

  // BAN/UNBAN
  socket.on('mod:kick', async ({targetUserId})=>{
    const srec=srecOrExit(socket,'mod:kick'); if(!srec||!srec.roomId) return;
    let targetSid=null,target=null; for(const [sid,rec] of sockets.entries()) if(rec.userId===targetUserId){ targetSid=sid; target=rec; break; }
    if(!targetSid||!target) return; if(['admin','sysop'].includes(target.globalRole)) return;
    const higher = rankOfRole(target.effectiveRole) >= rankOfRole(srec.effectiveRole); if(higher && srec.effectiveRole!=='owner') return;
    presence.get(srec.roomId)?.delete(targetSid); io.sockets.sockets.get(targetSid)?.leave(srec.roomId); sockets.get(targetSid).roomId=null;
    io.to(srec.roomId).emit('room:user_list', await buildUserList(srec.roomId));
    io.to(targetSid).emit('mod:kicked',{roomId:srec.roomId}); io.to(srec.roomId).emit('chat:system',{ text:`${target.username} è stato espulso`, kind:'info', ts:Date.now() });
  });

  socket.on('mod:ban', async ({targetUserId, durationMinutes=0, reason=''})=>{
    const srec=srecOrExit(socket,'mod:ban'); if(!srec||!srec.roomId) return;
    let targetSid=null,target=null; for(const [sid,rec] of sockets.entries()) if(rec.userId===targetUserId){ targetSid=sid; target=rec; break; }
    if(!target) {
      const tuser = await db.get('SELECT id, username, global_role FROM users WHERE id=?',[targetUserId]); if(!tuser) return;
      target = { userId:tuser.id, username:tuser.username, globalRole:tuser.global_role, effectiveRole:tuser.global_role, roomId:srec.roomId };
    }
    if(['admin','sysop'].includes(target.globalRole)) return;
    const higher = rankOfRole(target.effectiveRole) >= rankOfRole(srec.effectiveRole); if(higher && srec.effectiveRole!=='owner') return;
    const until = durationMinutes>0 ? (Date.now() + durationMinutes*60*1000) : null;
    await db.run('INSERT OR REPLACE INTO room_bans (room_id,user_id,reason,until_ts,created_at) VALUES (?,?,?,?,?)',[srec.roomId,target.userId, String(reason||''), until, Date.now()]);
    io.to(srec.roomId).emit('chat:system',{ text:`${target.username} è stato bannato${until?` fino a ${new Date(until).toLocaleString()}`:''}.`, kind:'info', ts:Date.now() });
    if(targetSid){ presence.get(srec.roomId)?.delete(targetSid); io.sockets.sockets.get(targetSid)?.leave(srec.roomId); sockets.get(targetSid).roomId=null; io.to(targetSid).emit('mod:kicked',{roomId:srec.roomId}); }
    io.to(srec.roomId).emit('room:user_list', await buildUserList(srec.roomId));
  });

  socket.on('mod:unban', async ({targetUserId})=>{
    const srec=srecOrExit(socket,'mod:unban'); if(!srec||!srec.roomId) return;
    if(!(srec.effectiveRole==='owner'||srec.globalRole==='admin'||srec.effectiveRole==='mod')) return;
    await db.run('DELETE FROM room_bans WHERE room_id=? AND user_id=?',[srec.roomId, targetUserId]);
    io.to(srec.roomId).emit('chat:system',{ text:`Utente sbloccato dal ban`, kind:'info', ts:Date.now() });
  });

  // ROLES
  socket.on('room:role_set', async ({targetUserId,role})=>{
    const srec=srecOrExit(socket,'room:role_set'); if(!srec||!srec.roomId) return;
    if(!['owner','mod','user'].includes(role)) return; if(!(srec.effectiveRole==='owner'||srec.globalRole==='admin')) return;
    let targetSid=null,target=null; for(const [sid,rec] of sockets.entries()) if(rec.userId===targetUserId){ targetSid=sid; target=rec; break; }
    if(!target) return; if(['admin','sysop'].includes(target.globalRole)) return;
    if(role==='user'){ await db.run('DELETE FROM room_roles WHERE room_id=? AND user_id=?',[srec.roomId,targetUserId]); }
    else { await db.run('INSERT OR REPLACE INTO room_roles (room_id,user_id,role) VALUES (?,?,?)',[srec.roomId,targetUserId,role]); }
    if(target.roomId===srec.roomId){ target.effectiveRole=userEffectiveRole(target.globalRole, role==='user'?'user':role); }
    if(['owner','mod'].includes(role)){
      const txt=role==='owner'
        ? `${target.username} è stato nominato owner`
        : `${target.username} è stato nominato moderatore`;
      io.to(srec.roomId).emit('chat:system',{ text:txt, kind:'info', ts:Date.now() });
    }
    io.to(srec.roomId).emit('room:user_list', await buildUserList(srec.roomId));
  });

  socket.on('disconnect', async ()=>{
    const srec=sockets.get(socket.id); if(!srec) return;
    if(srec.roomId){ presence.get(srec.roomId)?.delete(socket.id); io.to(srec.roomId).emit('room:user_list', await buildUserList(srec.roomId)); }
    sockets.delete(socket.id);
  });
});

server.listen(PORT, ()=> logger.info(`Berry Chat server running on http://localhost:${PORT}`));