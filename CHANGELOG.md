# Changelog

## 1.6.0
- **Install the Iran side from the foreign server only.** `install.sh` now asks "Set up an Iran server now?"; it needs just the Iran IP and root password,
  installs the panel over SSH (password via askpass, temporary key removed afterwards), negotiates GRE6 -> GRE4 -> direct with a real traffic test,
  optimises the tunnel on both ends, links sync and prints a summary. Also `fwpanel add-iran`, `install.sh --iran HOST|--no-iran`, and a wizard in the panel with live progress.
- **One-line command mode:** a one-time `/dl/<token>` installer served by the foreign panel (no SSH, no GitHub) that deletes itself after installing.
- **Tunnel engine:** tunnels card with health test (loss / RTT / jitter), PMTU discovery with DF pings, MTU = path MTU - GRE overhead, TCP MSS clamp (mangle chain),
  kernel tuning (BBR, fq, buffers, rp_filter, ip_forward), one-click repair, restart, delete, manual MTU.
- Removed `setup-servers.sh` / `--setup` (replaced by the above).

## 1.5.0
- GRE4 (GRE over IPv4) tunnels next to GRE6: tunnel type choice in the "add Iran server" wizard, `--kind gre4|gre6` in the installer,
  `--tunnel-type auto|gre6|gre4` in the two-server setup script (auto = GRE6 over a working IPv6 pair, otherwise GRE4).

## 1.4.0
- One-line online installer (`install.sh`, x-ui style) that downloads the latest release from GitHub; interactive port/protocol questions.
- `fwpanel` management command with a menu (start/stop/restart/status/log, password, port, HTTP/HTTPS, allow-list, update, uninstall).
- Repository reorganised (`src/`, `scripts/`, `tools/`, `docs/`), new README (Persian + English) with screenshots.
- Fix: upgrading no longer resets the panel port to 9443.
- `setup-servers.sh` can be run straight from GitHub: it downloads the panel on your machine and pushes it to the servers over SSH.

## 1.3.0
- `setup.sh` / `build_installer.py --setup`: one command sets up the panel on the foreign server and every Iran server,
  picks a working IPv6 pair, creates the GRE6 tunnel on both sides, links them for sync and creates the first forwards.
- Local admin CLI (`fwpanel.py admin METHOD PATH [JSON|-]`): talks to the running panel on 127.0.0.1 with a root-only token (no password).
- An existing sync key is never replaced silently (`--replace-key` is required).

## 1.2.0
- Panel settings from the UI: port, HTTP/HTTPS, IP allow-list (never locks you out: your own IP is kept).
- "Add Iran server" wizard: generates a self-extracting installer for the Iran side (optionally creates the
  GRE6 tunnel on both servers) and links it for automatic rule sync.
- Standalone installer builder (`build_installer.py`), `install.sh` flags, `uninstall.sh`.
- sshd ports are detected and protected from forwards.
- Synced rules become editable again when receiving is turned off.

## 1.1.0
- Persistent traffic totals per forward and per interface (survive restarts and reboots), reset buttons,
  editable interface names, Persian digits and units, bundled Vazirmatn font.
- Live traffic card with sparkline.
- Multi-panel rule sync over HMAC-signed requests (works over plain HTTP).

## 1.0.0
- iptables port forwarding (DNAT) manager: TCP / UDP / both, NAT toggle, persistent rules,
  watchdog that restores rule order, import/export, password-protected web panel.
