# SSHMemo Server

A lightweight web UI companion for the SSH Memo Android app [SSH Memo](https://play.google.com/store/apps/details?id=fi.dreamr.sshtodo)

It reads and writes the same Markdown files used by the app, letting you view, create, and edit your tasks and notes from any browser — on your own server, under your own control.

---

## What it is

SSH Memo stores all data as plain Markdown files on an SSH server you own. This web server runs alongside those files and provides a browser interface to them. It is entirely optional — the Android app works without it.

- View and edit tasks and notes in a browser
- Month calendar view with tasks, notes and calendar items; create, edit and delete calendar items
- Renders Markdown, including checklists
- Supports all item types: todos, notes, and custom categories
- Lists private (encrypted) items by name only — they are opened on the device that created them
- No database, no cloud, no accounts — just files
- Runs as a systemd service

---

## Requirements

- Python 3.7 or newer
- A Linux host with systemd (for the installer)
- The SSH Memo app's data directory accessible on the same machine

---

## Installation

Clone the repository anywhere on the server — it does **not** need to be inside your SSH Memo data folder:

```bash
git clone https://github.com/mrdreamr/sshmemoserver
cd sshmemoserver
bash install.sh
```

The installer will ask for the path to your SSHMemo sync folder (the directory the app writes its Markdown files into), then:

1. Create a Python virtualenv in the repository directory
2. Install dependencies (`flask`, `markdown`, `nh3`)
3. Register and start a `sshmemo` systemd service running as the current user, pointed at the data directory you specified

Re-running `install.sh` is safe — it updates an existing installation.

**Check status:**
```bash
sudo systemctl status sshmemo
sudo journalctl -u sshmemo -f
```

---

## Configuration

The server is configured through the SSH Memo Android app. In Settings, set the web server password for your user. This writes a `.sshmemo_web.meta` file in the root of your data directory, which the server reads at startup.

If no `.sshmemo_web.meta` is present or no users are configured in it, the server will not accept any logins.

### Port, host, and data directory

The service file at `/etc/systemd/system/sshmemo.service` contains the full startup command. Edit the `ExecStart` line to change any of these:

```ini
ExecStart=/path/to/venv/bin/sshmemo --root /path/to/data --host 0.0.0.0 --port 9000
```

Then reload:
```bash
sudo systemctl daemon-reload
sudo systemctl restart sshmemo
```

> **Note:** If you expose the server to the internet, put it behind a reverse proxy (nginx,
> Caddy) with HTTPS. The server itself does not handle TLS.

---

## File format

All data is stored as standard Markdown files, readable and editable by any text editor. The server uses the same format as the app — files written by one are fully compatible with the other.

```
# Task or note title
Done: true
Remind: 2025-06-01T09:00
Category: Work
Attachment: <id>|<mimeType>|<filename>

Body text in Markdown.
```

Private items are encrypted by the device that created them and stored as `.<name>.enc`. The server never decrypts them: it shows only the item's name, with a note to open it on that device. Items created or edited on the server are never private.

---

## Directory layout

The server expects the SSH Memo data directory structure:

```
<data-root>/
  <username>/
    todo/          ← task files (*.md)
    note/          ← note files (*.md)
    calendar/      ← calendar items (*.md, private items as .*.enc)
    repeated_todo/ ← repeated items (repeated calendar events shown read-only)
    custom/
      <category>/  ← custom category note files
        .meta      ← category name, icon, color
  shared/
    todo/
    note/
    calendar/
  .sshmemo_web.meta  ← user credentials (written by app)
```

---

## Security considerations

This server is designed for **personal, self-hosted use** — typically on a home server or a machine accessible only over a VPN or local network. It is not hardened for exposure to the public internet without additional protection.

Known limitations to be aware of:

- **Authentication is simple by design.** The login password is stored base64-encoded (not hashed) in `.sshmemo_web.meta`. Keep the data directory permissions tight and do not share the host with untrusted users.
- **No built-in HTTPS.** All traffic, including the login, is unencrypted unless you place the server behind a reverse proxy (nginx, Caddy) that handles TLS. Do not expose the server over the internet without this.
- **No brute-force protection.** There is no rate limiting on login attempts. If the server is reachable from the internet, a reverse proxy or firewall rule to restrict access is strongly recommended.
- **Sessions reset on restart.** Active login sessions are invalidated whenever the server process restarts.

For typical home-server or LAN use these limitations are acceptable. For anything more exposed, add a reverse proxy with HTTPS and consider restricting access by IP or requiring a VPN.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `flask` | HTTP server and routing |
| `nh3` | Sanitising rendered Markdown HTML |
| `markdown` | Rendering Markdown to HTML |

---

## License

GNU Affero General Public License v3.0 — see [agpl-3.0.txt](agpl-3.0.txt).

You are free to use, modify, and self-host this software. If you distribute a modified version or run it as a network service, you must make the source available under the same license.