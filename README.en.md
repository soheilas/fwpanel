<div align="center">

# fwpanel

**A tiny web panel for iptables port forwarding**
TCP / UDP · live traffic · GRE6 tunnels · automatic multi-server sync

English · [فارسی](README.md)

![dashboard](docs/screenshots/dashboard.jpg)

</div>

---

## Install (one line)

On a Debian / Ubuntu server, as root:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/soheilas/fwpanel/main/install.sh)
```

It asks a couple of questions (panel port and protocol), installs the panel and prints the **address and password**.
Afterwards the `fwpanel` command manages it.

## Features

- Port forwards (DNAT) for TCP, UDP or both; NAT toggle; enable/disable; persistent across reboots
- Live speed and **persistent totals** (survive restarts/reboots) per forward and per network interface, with reset buttons
- **Multi-server sync:** a forward created on the foreign server is created on your Iran servers automatically
- Persistent GRE6 tunnels with automatic discovery of a working IPv6 pair
- IP allow-list, login rate limit, optional HTTPS, HMAC-signed sync requests
- One dependency-free Python file, about 15 MB of RAM. The UI is Persian (RTL).

![rules](docs/screenshots/rules.jpg)

## Manage it: the `fwpanel` command

```
fwpanel                 management menu
fwpanel info            address, port, protocol
fwpanel status | log    state and logs
fwpanel start | stop | restart
fwpanel password        set a new password
fwpanel port [N]        change the panel port
fwpanel tls on|off      HTTPS / HTTP
fwpanel allow-clear     remove the IP allow-list (if you locked yourself out)
fwpanel update          update to the latest release
fwpanel uninstall       remove it
```

## Two servers (foreign + Iran) in one command

```bash
bash <(curl -Ls https://raw.githubusercontent.com/soheilas/fwpanel/main/scripts/setup-servers.sh) \
     --foreign 1.2.3.4 --iran 5.6.7.8 --key ~/.ssh/id_ed25519 \
     --rule 443=91.1.2.3 --rule 2087=65.1.2.3:2087
```

Installs the panel on both servers, finds a working IPv6 pair, creates the tunnel, links the panels and creates your first forwards.
Runs on any Linux / WSL / Git Bash with root SSH access to the servers (files are pushed over SSH: the servers do not need GitHub access).
Repeat `--iran` for more servers, `--foreign local` to run it on the foreign server, `--no-tunnel` for a direct connection,
`--replace-key` to take over an Iran server that already syncs from another panel. After that, create forwards **only in the foreign panel**.

For servers without GitHub access, the foreign panel can generate a self-contained installer for the Iran side
(Settings → add Iran server).

## Notes

- Passwords use PBKDF2; cookies are `HttpOnly` + `SameSite=Strict`. On plain HTTP the password is not encrypted: use the IP allow-list or HTTPS for internet-facing panels.
- Ports 22, sshd ports and the panel port cannot be forwarded (so you cannot lock yourself out).
- Some data centers filter auto-generated (SLAAC, `ff:fe`) IPv6 addresses; the setup script prefers static ones.
- The panel runs as root (needed for iptables) and forwards IPv4 only.

## License

Free to install and use on your own servers; redistribution, resale and offering it as a service require permission ([LICENSE](LICENSE)).
The bundled Vazirmatn font is under the SIL OFL 1.1.
