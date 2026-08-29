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
- 🗄️ **File System Storage Layer**: No external DB needed. Read/write concurrency is managed safely via mutexes.
- 🔐 **E2EE Transport**: The server handles ciphertext and encrypted keys as opaque data.
- 👥 **Admin-Approved Joining**: Prevent spam bots with a manual application workflow.
- 📦 **One Process, One Group**: The isolation layer is built directly into the server's core design.
- 🚀 **Dockerized Deployment**: Pack it, ship it, run it anywhere.

## Tech Stack

- **Language**: Go (1.21+)
- **Storage**: Plain Text Files & Flat Directories (`0700/0600` permissions)
- **Dependencies**: `golang.org/x/crypto/bcrypt`, `github.com/google/uuid`

## Quick Start (For Self-Hosters)

### 1. Compile and Run

```bash
git clone https://github.com/your-username/sov-server.git
cd sov-server
go mod tidy
go run main.go -port=8443 -dir=./data -admin=alice -admin-pass=your_password
```

### 2. Docker Run

```bash
docker build -t sov-server .
docker run -d \
  -p 8443:8443 \
  -v $(pwd)/data:/data \
  --name sov-server \
  sov-server -port=8443 -dir=/data -admin=alice -admin-pass=your_password
```

## Backend API Design

All authenticated operations rely on `X-User-Id` and `X-Password` request headers.

### Server Info
- `GET /health`: Returns service health and group stats.

### Member Management (Admin Flow)
- `POST /members/apply`: User requests to join.
- `GET /members/pending`: Admin views pending applications.
- `POST /members/approve`: Admin approves a user.
- `POST /members/reject`: Admin rejects a user.
- `POST /members/leave`: User leaves the group.
- `POST /members/set-password`: User changes own password, or admin resets it.

### Messaging (E2EE)
- `POST /chat/send`: Accepts encrypted payloads and routes them to the local log file.
- `GET /chat/messages`: Reads historical encrypted messages.

### Files (E2EE)
- `POST /files/upload`: Stores encrypted file blobs.
- `POST /files/upload-key`: Stores encrypted file keys.
- `GET /files/download`: Retrieves encrypted file blobs with strict path validation.

## API Security

- **Brute-Force Shield**: 5-second lockout after 5 failed login attempts.
- **Path Traversal Protection**: Enforces that requested files are strictly under the data root.
- **Concurrency Safety**: Mutex-protected file writes.

## License

MIT