# PT Proxy

PT Proxy runs several censorship-circumvention tunnels from one JSON config. Start a server, a client, or both in the same process. Each tunnel exposes a local SOCKS5 proxy (or an HTTP CONNECT proxy for DPI) and forwards traffic through the transport you pick.

If this project helps you, consider leaving a star — it helps others find it.

## Quick start

```bash
go build -o ptproxy ./main/
./ptproxy -c config.json
```

Generate an obfs4 certificate for a server entry:

```bash
./ptproxy -gencert
```

Open `config-builder.html` in a browser to build a config visually, then copy or download the JSON.

## Config shape

```json
{
  "server": [ { "type": "obfs4", "listen": "0.0.0.0:3334" } ],
  "client": [ { "type": "obfs4", "listen": "127.0.0.1:1080", "address": "1.2.3.4:3334", "cert": "..." } ]
}
```

Both `server` and `client` are optional arrays. Omit either key when you do not need it.

Common fields:

| Field | Role |
|-------|------|
| `type` | Transport name (see below) |
| `listen` | Local or public bind address |
| `address` | Remote server (host:port or URL, depending on type) |
| `external` | obfs only: use an external SOCKS exit instead of the built-in one |

Logs use tags like `[dpi-1080]` so you can tell entries apart when several run together.

## Tunnel types

### obfs2 / obfs3 / obfs4

Classic Tor pluggable transports. The server listens for obfuscated traffic; the client offers SOCKS5 on `listen` and connects to the server at `address`.

- **Server:** `listen`, optional `cert` / `private-key` (obfs4; auto-generated on first run if empty)
- **Client:** `listen`, `address`, `cert` (obfs4 server certificate)

Use `-gencert` to print a fresh obfs4 cert/key pair for manual config.

### DPI (HTTP/HTTPS tunnel)

Traffic is wrapped in encrypted HTTP requests so it looks like normal web traffic. Good when only HTTPS (or a specific site behind a rewrite) is allowed.

- **Server:** `http`, `https`, `enc-key`, TLS options (`tls-cert`/`tls-key`, `self-signed`, or ACME), optional `redirect`
- **Client:** `address` (e.g. `https://1.2.3.4:443`), `listen` (SOCKS5), optional `http-proxy`, `sni`, `front-host`, `enc-key`, `uplink`

**Fronting:** put the dial IP in `address`, set `sni` and `front-host` to the allowed hostname.

**Uplink mode** (`uplink` on the client):

- `post-async` (default) — separate POST requests, several in flight. Works behind Cloudflare, Vercel rewrites, and similar proxies.
- `stream` — one long upload stream and a shared download. Faster on a direct server; often breaks behind buffering CDNs.

### Snowflake

WebSocket-based relay. The server accepts WebSocket connections and runs a local SOCKS exit; the client connects over `ws://` or `wss://` and exposes SOCKS5 locally.

- **Server:** `listen` (WebSocket), `socks-bind`, optional TLS for WSS
- **Client:** `address` (WebSocket URL), `listen`, optional `sni`, `front-host`, `proxy`, `forward-bind`, `insecure`

### FTP tunnel

An FTP/FTPS façade hides persistent upload/download data channels. The server speaks FTP; the client offers SOCKS5 and uses PASV to bootstrap channels.

- **Server:** `listen`, `user`, `pass`, `enc-key`, `pasv-ip`, `upload-ports`, `download-ports`, optional TLS
- **Client:** `address` (FTP host:port), `listen`, credentials, `enc-key`, channel counts, optional `override-up-addr` / `override-down-addr`, `decoy`

## Typical setups

**Bridge on a VPS (obfs4):** one server entry with `listen` on a public port. Clients point `address` at that host and paste the server `cert`.

**DPI through a allowed website:** server on your origin (or behind a rewrite). Client uses `address` with the front IP, `sni`/`front-host` with the allowed domain, `uplink: post-async`.

**Local testing:** run server and client entries in one config; point the client at `127.0.0.1` and the server port.

## Build

Requires Go 1.24+.

```bash
go build -o ptproxy ./main/
```

Windows:

```bash
go build -o ptproxy.exe ./main/
```

## License

See repository license file.
