<div align="center">

# fwpanel

**A tiny web panel for iptables port forwarding**
TCP / UDP · live traffic · GRE4 / GRE6 tunnels with automatic tuning and repair · multi-server sync

English · [فارسی](README.md)

![dashboard](docs/screenshots/dashboard.jpg)

</div>

---

## Install (one line, **on the foreign server only**)

On the foreign Debian / Ubuntu server, as root:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/soheilas/fwpanel/main/install.sh)
```

It installs the panel and prints the **address and password**, then asks:

> **Set up an Iran server now? [y/N]**

Answer `y` and it only needs the **Iran server's IP and root password**. Everything else is automatic: SSH in, install the panel there,
pick the best tunnel (GRE6 → GRE4 → direct) by **really passing traffic through it**, tune it (MTU / MSS / kernel), link rule sync and print a **final summary**.
The password lives in memory only; the temporary SSH access is removed when the job ends.

You never install anything by hand on the Iran server. To add more Iran servers later use `fwpanel add-iran`
or the **Add Iran server** button in the panel.

### No SSH, or you don't want to hand over the password? One-line mode
In the panel: **Add Iran server → one-line command**. The panel gives you a short command to paste on the Iran server.
The installer is fetched from the foreign server (no GitHub needed), works once, and **deletes itself** after installing.

## Features

- Port forwards (DNAT) for TCP, UDP or both; NAT toggle; enable/disable; persistent across reboots
- Live speed and **persistent totals** per forward and per network interface, with reset buttons
- **Multi-server sync:** a forward created on the foreign server is created on your Iran servers automatically
- **GRE6** (IPv6) and **GRE4** (IPv4) tunnels with **health test**, **optimisation** and **one-click repair**
- IP allow-list, login rate limit, optional HTTPS, HMAC-signed sync requests
- One dependency-free Python file, about 15 MB of RAM. The UI is Persian (RTL).

![rules](docs/screenshots/rules.jpg)

## Tunnels: test, optimise, repair

The **Tunnels** card shows each tunnel's state (healthy / degraded / down), packet loss, latency and MTU.

- **Test:** real pings through the tunnel (loss, latency, jitter) plus a check of the outer path
- **Optimise:** large DF pings find the real path MTU, then `tunnel MTU = path MTU - GRE overhead` (GRE4 24, GRE6 44) is applied and saved;
  TCP MSS clamping is enabled on the tunnel; kernel tuning (BBR, fq, buffers, loose `rp_filter`, `ip_forward`)
- **Repair:** a down tunnel gets its interface, address, MTU, routes and systemd unit checked and fixed
- Tunnels are persistent systemd services and come back after a reboot

## Manage it: the `fwpanel` command

```
fwpanel                 management menu
fwpanel add-iran        set up an Iran server automatically (SSH)
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

After setup, create forwards **only in the foreign panel**; they appear on the Iran servers by themselves.
Each Iran server syncs from one foreign panel only.

## Notes

- Passwords use PBKDF2; cookies are `HttpOnly` + `SameSite=Strict`. On plain HTTP nothing is encrypted: use the IP allow-list or HTTPS for internet-facing panels. If you type the Iran root password in the panel over HTTP, do it from a trusted network (or use `fwpanel add-iran` in a terminal).
- GRE4 needs IP protocol 47 open between the servers; if it is blocked the installer falls back by itself.
- Some data centers filter auto-generated (SLAAC, `ff:fe`) IPv6 addresses; static ones are preferred.
- Ports 22, sshd ports and the panel port cannot be forwarded.
- The panel runs as root (needed for iptables) and forwards IPv4 only.

## License

Free to install and use on your own servers; redistribution, resale and offering it as a service require permission ([LICENSE](LICENSE)).
The bundled Vazirmatn font is under the SIL OFL 1.1.
