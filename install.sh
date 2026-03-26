#!/usr/bin/env bash
# SSHMemo server installer
# Run this script on the target host from the directory containing the server files:
#   bash install.sh
# Re-running is safe — it updates an existing installation.

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="sshmemo"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CURRENT_USER="$(whoami)"

echo "==> Install dir : $INSTALL_DIR"
echo "==> Venv        : $VENV_DIR"
echo "==> Service user: $CURRENT_USER"

# ── 1. Create virtualenv ────────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo "==> Creating virtualenv..."
    python3 -m venv "$VENV_DIR"
else
    echo "==> Virtualenv already exists, skipping creation."
fi

# ── 2. Install requirements from pyproject.toml ─────────────────────────────
echo "==> Installing requirements..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -e "$INSTALL_DIR"

# ── 3. Write systemd service file ───────────────────────────────────────────
echo "==> Installing systemd service to $SERVICE_FILE ..."
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=SSHMemo web server
After=network.target

[Service]
User=$CURRENT_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/sshmemo
Restart=always
Environment=FLASK_ENV=production

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"

# ── 4. Start / restart the service ──────────────────────────────────────────
echo "==> Starting service..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    sudo systemctl restart "$SERVICE_NAME"
    echo "==> Service restarted."
else
    sudo systemctl start "$SERVICE_NAME"
    echo "==> Service started."
fi

# add empty meta file
touch "$INSTALL_DIR/.sshmemo_web.meta"

echo ""
echo "Done. Check status with:  sudo systemctl status $SERVICE_NAME"
echo "View logs with:           sudo journalctl -u $SERVICE_NAME -f"
