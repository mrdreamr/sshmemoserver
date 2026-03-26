# SSHMemo Server

A lightweight web UI companion for the SSH Memo Android app (Currently in closed testing, update 
will happen on release).

It reads and writes the same Markdown files used by the app, letting you view, create, and edit your tasks and notes from any browser — on your own server, under your own control.

---

## What it is

SSH Memo stores all data as plain Markdown files on an SSH server you own. This web server runs alongside those files and provides a browser interface to them. It is entirely optional — the Android app works without it.

- View and edit tasks and notes in a browser
- Renders Markdown, including checklists
- Supports all item types: todos, notes, and custom categories
- Decrypts and displays private (encrypted) items if you provide your passphrase
- No database, no cloud, no accounts — just files
- Runs as a systemd service

---

## Requirements

- Python 3.7 or newer
- A Linux host with systemd (for the installer)
- The SSH Memo app's data directory accessible on the same machine

---

## Installation

Clone the repository onto the server that hosts your SSH Memo files:

```bash
git clone https://github.com/mrdreamr/sshmemoserver
cd sshmemoserver
bash install.sh
```

The installer will:
1. Create a Python virtualenv in the project directory
2. Install dependencies (`flask`, `cryptography`, `markdown`)
3. Register and start a `sshmemo` systemd service running as the current user

Re-running `install.sh` is safe — it updates an existing installation.

**Check status:**
```bash
sudo systemctl status sshmemo
sudo journalctl -u sshmemo -f
```

---

## Configuration

The server is configured through the SSH Memo Android app. In Settings, set the web server password for your user. This writes a `.sshmemo_web.meta` file in the root of your data directory, which the server reads at startup.

The password doubles as the passphrase for decrypting private/encrypted notes.

If no `.sshmemo_web.meta` is present or no users are configured in it, the server will not accept any logins.

### Port and host

By default the server listens on `localhost:8080`. To change this, edit the systemd service file at `/etc/systemd/system/sshmemo.service` and update the `ExecStart` line:

```ini
ExecStart=/path/to/venv/bin/sshmemo --host 0.0.0.0 --port 9000
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

Private items are AES-256-GCM encrypted with a key derived from your passphrase (PBKDF2-SHA256, 100 000 iterations). The server decrypts them in memory for display only — the files on disk remain encrypted.

---

## Directory layout

The server expects the SSH Memo data directory structure:

```
<data-root>/
  <username>/
    todo/          ← task files (*.md)
    note/          ← note files (*.md)
    shared/
      todo/
      note/
    custom/
      <category>/  ← custom category note files
        .meta      ← category name, icon, color
  .sshmemo_web.meta  ← user credentials (written by app)
```

---

## Security considerations

This server is designed for **personal, self-hosted use** — typically on a home server or a machine accessible only over a VPN or local network. It is not hardened for exposure to the public internet without additional protection.

Known limitations to be aware of:

- **Authentication is simple by design.** The login password is the same passphrase used to encrypt your private notes, so it must be stored in a recoverable form. Keep the data directory permissions tight and do not share the host with untrusted users.
- **No built-in HTTPS.** All traffic, including the login, is unencrypted unless you place the server behind a reverse proxy (nginx, Caddy) that handles TLS. Do not expose the server over the internet without this.
- **No brute-force protection.** There is no rate limiting on login attempts. If the server is reachable from the internet, a reverse proxy or firewall rule to restrict access is strongly recommended.
- **Sessions reset on restart.** Active login sessions are invalidated whenever the server process restarts.

For typical home-server or LAN use these limitations are acceptable. For anything more exposed, add a reverse proxy with HTTPS and consider restricting access by IP or requiring a VPN.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `flask` | HTTP server and routing |
| `cryptography` | AES-GCM decryption of private files |
| `markdown` | Rendering Markdown to HTML |

---

## License

GNU Affero General Public License v3.0 — see [agpl-3.0.txt](agpl-3.0.txt).

You are free to use, modify, and self-host this software. If you distribute a modified version or run it as a network service, you must make the source available under the same license.