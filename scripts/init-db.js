import 'dotenv/config';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import fs from 'fs';

const DB_FILE = process.env.DB_FILE || './data/msnchat.db';
fs.mkdirSync('./data', { recursive: true });

const db = await open({ filename: DB_FILE, driver: sqlite3.Database });

await db.exec(`
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  created_by TEXT,
  owner_user_id TEXT
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  room_id TEXT NOT NULL,
  user_id TEXT,
  user_name TEXT NOT NULL,
  user_role TEXT NOT NULL,
  text TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bans (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  ip TEXT,
  reason TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);
CREATE TABLE IF NOT EXISTS mutes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  room_id TEXT NOT NULL,
  reason TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);
`);

console.log('Database initialized at', DB_FILE);
await db.close();
