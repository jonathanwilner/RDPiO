# RDPiO Linux port

RDPiO is a Windows-native RDP/W365 client. This tracks the staged port to Linux.
The **portable protocol core** (`rdp-pdu`, `rdp-core`, `rdp-crypto`, `rdp-channels`,
`rdp-graphics`, `rdp-asn1`) is pure sans-I/O Rust and already cross-compiles.
Everything platform-specific lives behind `#[cfg(windows)]` / `#[cfg(unix)]` seams.

## Cross-compiling from Windows (dev/CI)

`ring` (via rustls) needs a Linux C toolchain. Use zig:

```
cargo install cargo-zigbuild
# zig 0.13 on PATH (e.g. C:\Users\<you>\zig)
# NOTE: the zig/lld linker mangles paths with spaces, so build into a space-free
# target dir when the checkout path contains spaces:
CARGO_TARGET_DIR=/c/rdpiotgt cargo zigbuild --target x86_64-unknown-linux-gnu -p rdp-client
```

On a real Linux host, a plain `cargo build` works (gcc is standard, no space issue).

## Stages

- [x] **Stage 1 — compile headless on Linux.** DONE. Gated Windows-only deps
  (`webview2-com`) and the W365/UI/platform modules (`websocket`, `reverse_connect`,
  `rdstls_auth`, `rdstls_v3`, `webview_auth`, `cloud_pc_picker`, `net_listener`)
  behind `cfg(windows)`; added a `Backend` stub to `rdp-gpu`; made the `AtomicU32`
  import unconditional. Produces a real `x86_64-unknown-linux-gnu` ELF binary that
  runs the protocol stack headless (TCP; the `#[cfg(not(windows))] run_connect`
  path). Windows build unaffected.
- [x] **Stage 2 — rustls TLS.** DONE. `tls_rustls.rs` provides a non-Windows
  `tls::TlsStream<S>` (rustls 0.23 + webpki-roots; `--insecure` → accept-any
  verifier) matching the SChannel API (`connect`, Read/Write, `get_ref`,
  `remote_cert_der`). `run_connect` now wraps the negotiated socket in TLS when the
  server selects SSL (Enhanced RDP Security) and runs activation headlessly; HYBRID
  (NLA) still warns (Stage 3). Builds for Linux and Windows.
- [x] **Stage 3 — NLA / CredSSP on Linux.** DONE. Lets the headless build connect
  to standard Windows RDP servers (which select NLA/HYBRID). `rdp-nla` already had
  portable `TSRequest` framing (`tsrequest.rs`) and public-key extraction
  (`x509.rs`); only the Win32 SSPI engine (`sspi.rs`) was Windows-only. Added a
  portable `credssp.rs` (`#[cfg(not(windows))]`): NTLMv2 (NEGOTIATE/CHALLENGE/
  AUTHENTICATE, NTLMv2 response, Extended Session Security sign+seal, key exchange,
  MIC) + the CredSSP public-key channel binding (SHA-256 nonce, v5+) + sealed
  `TSCredentials`. Added `md4` to `rdp-crypto` (the NT-hash primitive; everything
  else — MD5/HMAC-MD5/RC4/SHA-256 — was already in-tree). `run_connect` now wraps
  the socket in TLS for **both** SSL and HYBRID, runs `credssp::authenticate` over
  the tunnel for HYBRID (mirroring the Windows `connect.rs` path,
  `spn = TERMSRV/<host>`), then activates. Validated offline against the MS-NLMP
  §4.2.4 NTLMv2 test vectors + a seal/unseal round-trip (no Windows APIs, no new
  external crates). NLA is a one-time connection handshake, off every per-frame
  path, so this does not affect streaming performance.
- [ ] **Stage 4 — W365 on Linux.** *Partially done via integration.* The
  portable half of Stage 4 is complete: `w365.rs` (OAuth code/device flows,
  refresh, ARM feed discovery, `.rdp` resource download) and the feed parser
  now run on Linux, the token cache stores via the Secret Service with a `0600`
  XDG-state file fallback, and the interactive sign-in uses the system browser
  instead of WebView2. The login itself is teams-tui-go's: when teams-tui-go is
  configured, `teams_auth.rs` silently mints a W365 token from its cached
  refresh token (read-only — rdpio never writes to `~/.cache/teams-tui-go`),
  `browser_auth.rs::authenticate_loopback` is the PKCE + localhost-loopback
  browser flow (with a paste fallback) that tenants with device-code-blocking
  Conditional Access need, and the device flow uses teams-tui-go's
  registrations (`auth_flow`, `client_id`, `browser_client_id` from its
  `config.json`; `--w365-auth auto|browser|device|paste` overrides). The
  token cache records which registration minted a token so silent refresh
  uses the same one. `rdpio --w365` on Linux is a **FreeRDP integration
  backend**: rdpio discovers the workspace and downloads Microsoft's current
  signed `.rdp`, then hands it to an upstream FreeRDP 3 client
  (`/gateway:type:arm /sec:aad /dvc:rdpecam`), which owns the ARM gateway,
  RDSAAD session auth, the interactive session, and webcam redirection through
  its upstream MS-RDPECAM client (`CHANNEL_RDPECAM_CLIENT=ON`; the repo flake
  builds one via `nix develop` / `nix build .#freerdp-ecam`). This is a
  deliberate hand-off, not a port of rdpio's native W365 stack — porting
  RDSTLS v3, the ARM broker tunnel, rendering and RDPECAM natively remains
  future work tracked by the unchecked items below.
  - [x] Portable W365 auth + feed + `.rdp` download (`w365.rs`, `feed.rs`,
    `browser_auth.rs`, `token_cache.rs`, `teams_auth.rs`).
  - [x] FreeRDP session backend (`freerdp_backend.rs`): capability detection,
    verbatim `.rdp` in a `0600` temp file, argv-vector launch, camera policy
    (`--camera`/`--no-camera`), `--w365-doctor`.
  - [ ] Port the RDSTLS v3 credential (CNG AES/RSA/cert → RustCrypto) for a
    fully native session (not needed for the FreeRDP backend).
  - [ ] Port the native reverse-connect/ARM tunnel (not needed for the FreeRDP
    backend).
- [ ] **Stage 5 — interactive client.** Rendering (D3D11 → `wgpu`), window/input
  (Win32 → `winit`), H.264 decode (Media Foundation → `ffmpeg`/VA-API), audio
  (WASAPI → `cpal`/PipeWire).

## Notes

- `rdp-gpu` is Windows-only with a non-Windows stub already, so it links (no-op) on
  Linux; Stage 4 replaces the stub with a real backend.
- `main.rs` already has a `#[cfg(not(windows))]` `run_connect` headless path.
