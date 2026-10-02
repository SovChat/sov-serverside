# Sov Server

A **self-hosted, decentralized, end-to-end encrypted backend server** for group messaging.

If you are looking for a client, this is not it. This is the **core backend software** designed for administrators and developers who want to host their own sovereign chat networks.

## Why Sov?

Most communication platforms are built on centralized infrastructure. They hold your data, your keys, and your metadata. Sov stands against this.

- **Sovereign Data**: You own the server, you own the files, you own the data. Run it on your own VPS, your own NAS, or even your own Raspberry Pi.
- **Backend Only**: This is a headless Go server process. It exposes a strict API for your frontend clients to communicate with.
- **Zero-Knowledge**: The server stores encrypted blobs and routes them between users. It has absolutely no ability to read your messages.
- **File System Native**: Drop the database, drop the complexity. Your chat history exists as simple files that you can backup, copy, and archive.
- **One Group per Process**: Each server instance is dedicated to exactly one group, simplifying moderation and maximizing isolation.

## Target Audience

This project is for **System Administrators, Self-Hosters, and Developers** who want to build their own decentralized networks. If you are looking to create a client app, you can build on top of the REST API defined here.

## Core Features

- 🛡️ **Bcrypt (Cost=12) Authentication**: Passwords are hashed with extreme care.
- 🧾 **Account Registration & Login**: Accounts live in `accounts.txt`; a successful login issues a random session token (no cookies, no central auth service).
- 🚪 **Public vs Private Groups**: `-public=true` (default) means registration joins the group immediately; `-public=false` means registration only creates the account and the joining request waits for admin approval.
- 🗄️ **File System Storage Layer**: No external DB needed. Read/write concurrency is managed safely via mutexes.
- 🔐 **E2EE Transport**: The server handles ciphertext and encrypted keys as opaque data.
- 👥 **Admin-Approved Joining**: Prevent spam bots with a manual application workflow.
- 📦 **One Process, One Group**: The isolation layer is built directly into the server's core design.
- 🚀 **Dockerized Deployment**: Pack it, ship it, run it anywhere.

## Tech Stack

- **Language**: Go (1.22+, the router uses the `"METHOD /path"` patterns introduced in Go 1.22)
- **Storage**: Plain Text Files & Flat Directories (`0700/0600` permissions)
- **Dependencies**: `golang.org/x/crypto/bcrypt`, `github.com/google/uuid`

## Quick Start (For Self-Hosters)

### 1. Compile and Run

```bash
git clone https://github.com/your-username/sov-server.git
cd sov-server
go mod tidy
go run main.go -port=8443 -dir=./data -admin=alice -admin-pass=your_password -name="My Group" -public=true
```

### 2. Command Line Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-port` | `8443` | Listen port |
| `-dir` | `./data` | Data root (created automatically) |
| `-admin` | *(empty)* | Initial admin / founder userId |
| `-admin-pass` | *(empty)* | Initial admin password (≥6 chars); must be used together with `-admin` |
| `-name` | `Untitled Group` | Group name, stored in `serverinfo/name.txt` |
| `-public` | `true` | `true` = public channel: **registration joins the group immediately**; `false` = private group: registration only creates an account and the joining request waits for admin approval |

> The visibility is written to `serverinfo/visibility.txt` **on the first start only**. Later changes to `-public` do not rewrite it — edit that file (or remove the data dir) to switch. A data directory created before this feature (no `visibility.txt`) is treated as **private**, so an upgrade never silently opens a group to self-service registration.

### 3. Docker Run

```bash
docker build -t sov-server .
docker run -d \
  -p 8443:8443 \
  -v $(pwd)/data:/data \
  --name sov-server \
  sov-server -port=8443 -dir=/data -admin=alice -admin-pass=your_password -public=true
```

## Backend API Design

Every protected endpoint accepts **either** of the following identity mechanisms:

1. `Authorization: Bearer <token>` — the session token returned by `/auth/register` or `/auth/login` (**preferred**);
2. `X-User-Id` + `X-Password` request headers — the original stateless mechanism, kept for scripts and gradual migration.

### Server Info

- `GET /health`: Returns service health and group stats. No auth required.
  `{"status":"ok","name":"My Group","memberCount":3,"public":true}`

### Accounts & Sessions

- `POST /auth/register` (no auth): Creates an account and immediately issues a session token.
  ```bash
  curl -X POST http://localhost:8443/auth/register \
       -H "Content-Type: application/json" \
       -d '{"userId":"bob","password":"bobpass123","displayName":"Bob"}'
  ```
  Response:
  ```json
  {"success":true,"token":"<43-char token>","expiresAt":1790000000,
   "user":{"userId":"bob","displayName":"Bob","createdAt":"2026-10-02"},
   "isAdmin":false,"isMember":true,"group":{...},"joined":true,"pending":false,
   "message":"Account created, welcome"}
  ```
  - public channel → `joined=true`, `isMember=true`: the account is written to `members.txt` right away;
  - private group → `joined=false`, `pending=true`: the account is created and a pending request is registered in `unverified_members.txt`, so an admin can approve it later. The user **can log in** but cannot read or send messages until approved.
- `POST /auth/login` (no auth): `{"userId":"bob","password":"bobpass123"}` → same payload shape as register (with `token`/`expiresAt`). Unknown user and wrong password both return `401 {"error":"Auth failed: userId or psw wrong"}` to avoid username enumeration.
- `GET /auth/me`: Returns the current identity (`user`, `isAdmin`, `isMember`, `group`) for whichever credential was supplied.
- `POST /auth/logout`: Revokes the presented bearer token. Idempotent — it always returns `{"success":true}`, even if the token is missing or already invalid.

### Member Management (Admin Flow)

- `POST /members/apply`: User requests to join (needs a `publicKey`).
- `GET /members/pending`: Admin views pending applications.
- `POST /members/approve`: Admin approves a user.
- `POST /members/reject`: Admin rejects a user.
- `GET /members/list`: Member list (`userId`, `joinedDate`, `publicKey`, plus `displayName` joined from `accounts.txt`). No auth required — public keys are public.
- `POST /members/leave`: User leaves the group (only for their own `userId`).
- `POST /members/set-password`: User changes own password, or admin resets someone else's. When called with a session token, the old password is not required (the token already proves identity); all *other* sessions of that user are revoked afterwards.

### Messaging (E2EE)

- `POST /chat/send`: Accepts encrypted payloads and routes them to the local log file.
- `GET /chat/messages?date=YYYY-MM-DD&since=<unix seconds>`: Reads historical encrypted messages.

### Files (E2EE)

- `POST /files/upload`: Stores encrypted file blobs.
- `POST /files/upload-key`: Stores encrypted file keys.
- `GET /files/download?path=files/...`: Retrieves encrypted file blobs with strict path validation.

## Data Layout

```
data/
├── serverinfo/
│   ├── name.txt                 # group name
│   ├── created_date.txt
│   ├── founder.txt
│   ├── visibility.txt           # "public" | "private" (written on first start)
│   ├── accounts.txt             # one JSON account per line: {"userId","displayName","createdAt"}
│   └── passwords/{userId}.hash  # bcrypt hash, cost=12
├── serverpersons/
│   ├── admins.txt
│   ├── members.txt              # userId|joinedDate|publicKey
│   └── unverified_members.txt   # userId|requestDate|publicKey
├── memberprofiles/              # reserved for avatars
├── chat/{YYYY-MM-DD}.log        # timestamp|senderId|ciphertext|encryptedKeysJson
└── files/{YYYY-MM-DD}/{fileId}.enc|.keys
```

## API Security

- **Brute-Force Shield**: after 5 consecutive failures for the same `userId`, every further failure is delayed by 5 seconds before responding. The counter is reset by a successful verification.
- **Session Tokens**: 32 bytes from `crypto/rand`, base64url encoded, valid for 7 days. They are held **in memory only**, so a server restart invalidates every session (accounts and password hashes are on disk and unaffected) — clients simply log in again.
- **Uniform Login Errors**: an unknown user and a wrong password produce the same 401 message, so the API cannot be used to enumerate accounts.
- **Password Change Hardening**: changing a password revokes the user's other sessions while keeping the caller's own token alive.
- **Path Traversal Protection**: enforces that requested files are strictly under the data root.
- **Concurrency Safety**: Mutex-protected file writes, atomic `temp + rename` rewrites.

## License

MIT
