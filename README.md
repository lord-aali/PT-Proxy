# PT Proxy

PT Proxy is a single binary that runs censorship-circumvention tunnels from one JSON file. You can run a public bridge, a laptop client, or both in the same process.

You compose **services** (`socks`, `http`, `external`) and **tunnels** (obfs, DPI, Snowflake, FTP). Tags wire them for forward or reverse pipes.

`If this project helps you, consider leaving a star. ⭐`

## Quick start

```bash
go build -o ptproxy ./main/
./ptproxy -c config.json
```

```bash
./ptproxy -gencert
```

Open `config-builder.html` in a browser to build a config, then copy or download the JSON.

Full protocol instructions and implementation notes are the wiki in [`doc/`](doc/index.html) (open `doc/index.html` in a browser).

## How a forward tunnel works

A forward tunnel means: the interesting service lives on the **server** machine (or something that machine can reach), and you want it to show up on your laptop as a local port.

You declare the service in the `server` list — SOCKS5, HTTP CONNECT, or an existing process (`external`). Give it a `tag`, or let PT Proxy name it `type-port` after it binds. The tunnel server (obfs, DPI, Snowflake, FTP) sets `target` to that tag and pipes bytes there.

In client, the tunnel client binds `listen`. TCP and UDP share that same host:port and client connects to the tagged service through the obfuscated tunnel.

Order of events: the service starts and gets a tag → the tunnel server starts and points `target` at it → the client connects to `address` and binds `listen` → each local accept or datagram is one flow to the far side.

## How a reverse tunnel works

A reverse tunnel means: the interesting service is on **your** machine (or LAN), and you want the VPS to publish a port that reaches it.

The client still lists that service under `server`. That array means “services this process owns,” not “I am the public bridge.” The tunnel **client** sets `reverse-tag` to that tag and uses `listen` as the host:port that should appear **on the VPS**. The VPS tunnel entry has **no** `target`; it is only a hub. After the client connects, the hub binds that `listen` (TCP and UDP). Someone hitting the VPS port is forwarded back to the laptop service.

If `reverse-tag` is missing, PT Proxy logs an error and skips that client.

## Scenarios

### 1. Censored network, SOCKS on the VPS

You want a browser on a restricted network to use a SOCKS5 proxy that actually exits on your VPS.

**VPS**

```json
{
  "server": [
    { "type": "socks", "listen": "127.0.0.1:0", "tag": "exit" },
    { "type": "obfs4", "listen": "0.0.0.0:3334", "target": "exit" }
  ]
}
```

**Client**

```json
{
  "client": [
    { "type": "obfs4", "listen": "127.0.0.1:1080", "address": "<vps_ip>:3334", "cert": "..." }
  ]
}
```

The socks block picks a free loopback port; logs show the real tag if you omitted one. obfs4 pipes every tunnel connection to that SOCKS. In client, `127.0.0.1:1080` is a plain TCP+UDP bind. The browser speaks SOCKS to that port; the handshake rides the pipe and is answered by the VPS socks daemon. UDP associate uses the same port.

### 2. HTTP CONNECT instead of SOCKS

Same shape, `http` instead of `socks`. Point the OS or browser HTTP proxy at the client `listen`. CONNECT is TCP only; UDP on that pipe is ignored for an `http` target.

### 3. Fixed backend on the VPS (SSH, a game, DNS)

You already have something listening on the VPS — sshd, a game server, a DNS daemon — and you want `127.0.0.1:2222` in client to be that service.

**VPS**

```json
{
  "server": [
    { "type": "external", "listen": "127.0.0.1:22", "tag": "ssh" },
    { "type": "obfs4", "listen": "0.0.0.0:3334", "target": "ssh" }
  ]
}
```

**Client:**
```json
{
  "client": [
    { "type": "obfs4", "listen": "127.0.0.1:2222", "address": "<vps_ip>:3334", "cert": "..." }
  ]
}
```
client `listen` on `127.0.0.1:2222`. Then try `ssh -p 2222 127.0.0.1`.


`external` is not a listener. `listen` is the address to dial. The same pattern works for a UDP service on that port. TCP accepts and UDP packets both go to `host:port`. If the backend is TCP-only, UDP is simply unused.

### 4. Expose client's SSH on the VPS

sshd is in client machine. Third-party clients should `ssh <vps_ip> -p 2222`.

**Client**

```json
{
  "server": [
    { "type": "external", "listen": "127.0.0.1:22", "tag": "ssh" }
  ],
  "client": [
    { "type": "obfs4", "address": "<vps_ip>:3334", "cert": "...", "reverse-tag": "ssh", "listen": "0.0.0.0:2222" }
  ]
}
```

**VPS:** 
```json
{
  "server": [
    { "type": "obfs4", "listen": "0.0.0.0:3334", "cert": "..."}
  ]
}
```
Server config comes with no `target`, just a hub.

The client asks the hub to bind `0.0.0.0:2222`. Each connection there is dialed to `127.0.0.1:22` on the laptop.

### 5. Publish a local SOCKS on a public port
**VPS:**
```json
{
  "server": [
    { "type": "obfs4", "listen": "0.0.0.0:3334", "cert": "..."}
  ]
}
```
**Client:**
```json
{
  "server": [
    { "type": "socks", "listen": "127.0.0.1:0", "tag": "exit" }
  ],
  "client": [
    { "type": "obfs4", "address": "<vps_ip>:3334", "cert": "...", "reverse-tag": "exit", "listen": "0.0.0.0:1080" }
  ]
}
```
Run `socks` in the client `server` list, and a reverse client whose `reverse-tag` is that socks. The VPS binds a public port. Remote users speak SOCKS to the VPS; the daemon answering is on the laptop.


## Field cheat sheet

| Field | Where | Meaning |
|-------|--------|---------|
| `tag` | any block | Handle for `target` / `reverse-tag`. Default `type-port` after bind (port `0` uses the assigned port). |
| `target` | tunnel **server** | Pipe to this service tag. Omitted = reverse hub. |
| `reverse-tag` | tunnel **client** | Service tag in **this file’s** `server` list. Set = reverse; `listen` is the bind on the PT server. Omitted = forward; `listen` is local. |
| `listen` | socks/http | Bind address. Default `127.0.0.1:0`. |
| `listen` | external | Required dial address of the real backend. No default. |
| `user` / `pass` | socks | Optional SOCKS auth. Omitted = no auth. |

Client tunnel `listen` defaults to `127.0.0.1:1080`. Server obfs `listen` defaults to `0.0.0.0:3334`, Snowflake `0.0.0.0:8080`, FTP `0.0.0.0:21`, DPI HTTPS `0.0.0.0:443`.

Logs look like `[obfs4-3334]` so you can tell entries apart.

## Tunnel types (camouflage)

### obfs2 / obfs3 / obfs4

Classic obfuscated TCP (the Tor pluggable-transport family). **Server:** `listen`, optional `cert` / `private-key` (obfs4; generated on first run if empty), optional `target`. **Client:** `listen`, `address`, `cert`, optional `reverse-tag`. Carries TCP and UDP; can splice raw TCP to an `external` ORPort for Tor.

### DPI (HTTP/HTTPS tunnel)

Traffic is wrapped in encrypted HTTP. **Server:** `http` / `https`, `enc-key`, TLS (`tls-cert`/`tls-key`, `self-signed`, or ACME), optional `redirect`, optional `target`. **Client:** `address` (URL), `listen`, optional `sni`, `front-host`, `enc-key`, `uplink`.

Fronting: dial IP in `address`, `sni` and `front-host` set to the allowed hostname.

- `uplink: post-async` (default) — separate POSTs; works behind many CDNs.
- `uplink: stream` — one long upload; faster on a direct server. Reverse DPI uses stream.

### Snowflake

WebSocket relay with KCP/smux. **Server:** `listen` (ws/wss), optional TLS, optional `target`. **Client:** `address` (`ws://` or `wss://`), `listen`, optional `sni`, `front-host`, `proxy`, `insecure`. Forward and reverse, TCP and UDP.

### FTP tunnel

FTP/FTPS façade with persistent data channels. **Server:** `listen`, `user`, `pass`, `enc-key`, `pasv-ip`, port ranges, optional TLS, optional `target`. **Client:** `address` (FTP host:port), `listen`, credentials, channel counts, optional PASV overrides, `decoy`.

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
