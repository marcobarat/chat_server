# MSN Chat Clone — Server (Node.js + Socket.IO + SQLite + Logging)

## Requisiti
- Node.js 18+
- npm

## Setup
```bash
cd server
npm i
cp .env.example .env
# modifica .env: ADMIN_SHARED_SECRET, JWT_SECRET
npm run db:reset     # inizializza DB (rooms, messages, bans, mutes)
npm run dev          # avvia server
```

## Log
- Log su file rotanti in `./logs/` (`server-YYYY-MM-DD.log`, `error-YYYY-MM-DD.log`).
- Eventi loggati: connessioni, join/leave, messaggi, PM, AFK, creazione stanze, owner/ruoli, kick, ban, mute, errori.

## API
- `POST /api/admin/login` — `{ sharedSecret, adminName }` → `{ token }`
- `GET  /api/rooms` — lista stanze pubbliche
- `GET  /api/admin/overview` — **(admin)** rooms + utenti online
- `POST /api/admin/rooms/:roomId/owner` — **(admin)** body `{ userId }`
- `POST /api/admin/users/:userId/role` — **(admin)** body `{ role }` tra `mod|guide|sysop|admin`
- `POST /api/admin/users/:userId/kick` — **(admin)**
- `POST /api/admin/users/:userId/ban` — **(admin)** body `{ minutes, reason }` (ban per userId + IP)
- `POST /api/admin/users/:userId/unban` — **(admin)**
- `POST /api/admin/users/:userId/mute` — **(admin)** body `{ roomId, minutes, reason }` (mute per stanza)
- `POST /api/admin/users/:userId/unmute` — **(admin)** body `{ roomId }`

## Socket.IO (principali)
- `room:create` `{ name, description }`
- `room:list` → `rooms:list`
- `room:join` `{ roomId, name }` → `room:joined`, `room:user_list`
- `chat:message` `{ text }` → `chat:message`
- `chat:pm` `{ toUserId, text }` → `chat:pm`
- `user:afk` `{ afk }`
- `mod:kick` `{ targetUserId }`
