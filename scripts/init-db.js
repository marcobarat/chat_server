import 'dotenv/config';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import fs from 'fs';
import argon2 from 'argon2';
import { v4 as uuidv4 } from 'uuid';

const DB_FILE = process.env.DB_FILE || './data/berrychat.db';
fs.mkdirSync('./data', { recursive: true });
const db = await open({ filename: DB_FILE, driver: sqlite3.Database });

await db.exec(`
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  gender TEXT CHECK(gender IN ('M','F','O')) DEFAULT 'O',
  global_role TEXT CHECK(global_role IN ('user','mod','guide','sysop','admin')) DEFAULT 'user',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  owner_password TEXT,
  owner_password_hash TEXT,
  created_by TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS room_roles (
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  role TEXT CHECK(role IN ('owner','mod')) NOT NULL,
  PRIMARY KEY (room_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  room_id TEXT NOT NULL,
  user_id TEXT,
  user_name TEXT,
  user_role TEXT,
  kind TEXT DEFAULT 'chat',
  text TEXT NOT NULL,
  ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS room_bans (
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  reason TEXT,
  until_ts INTEGER, -- NULL = permanent
  created_at INTEGER NOT NULL,
  PRIMARY KEY (room_id, user_id)
);
`);

// Bootstrap admin/admin
const adminUser = process.env.ADMIN_BOOTSTRAP_USER || 'admin';
const adminPass = process.env.ADMIN_BOOTSTRAP_PASS || 'admin';
const adminGender = ['M','F','O'].includes((process.env.ADMIN_BOOTSTRAP_GENDER||'O')) ? process.env.ADMIN_BOOTSTRAP_GENDER : 'O';
const pass_hash = await argon2.hash(adminPass, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });

const byName = await db.get("SELECT id FROM users WHERE username = ?", [adminUser]);
if (!byName) {
  await db.run('INSERT INTO users (id, username, pass_hash, gender, global_role, created_at) VALUES (?,?,?,?,?,?)',
    [uuidv4(), adminUser, pass_hash, adminGender, 'admin', Date.now()]);
  console.log(`Seeded admin user: ${adminUser}/${adminPass}`);
} else {
  await db.run("UPDATE users SET pass_hash=?, global_role='admin' WHERE username=?", [pass_hash, adminUser]);
  console.log(`Ensured admin user and password for: ${adminUser}`);
}

console.log('Database initialized at', DB_FILE);
await db.close();