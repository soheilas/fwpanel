# Changelog

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
