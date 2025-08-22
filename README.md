# Berry Chat Server

## HTTPS configuration

This server now expects an HTTPS certificate and key. Generate a self‑signed pair for development:

```bash
mkdir -p certs
openssl req -newkey rsa:2048 -nodes -keyout certs/server.key -x509 -days 365 -out certs/server.crt
```

Set the following environment variables so the server can load the certificate:

```
TLS_CERT_PATH=./certs/server.crt
TLS_KEY_PATH=./certs/server.key
```

Clients should connect using `https://` (or `wss://` for WebSocket) URLs.

