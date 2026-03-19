#!/bin/bash
# arkd-rs systemd installation helper
set -euo pipefail

echo "==> Creating arkd user and directories..."
sudo useradd -r -m -d /var/lib/arkd -s /bin/false arkd 2>/dev/null || true
sudo mkdir -p /etc/arkd /var/lib/arkd
sudo chown arkd:arkd /var/lib/arkd

echo "==> Installing config template..."
if [ ! -f /etc/arkd/config.toml ]; then
    sudo cp contrib/config.example.toml /etc/arkd/config.toml
    echo "    Edit /etc/arkd/config.toml with your settings"
else
    echo "    /etc/arkd/config.toml already exists, skipping"
fi

echo "==> Installing systemd service..."
sudo cp contrib/arkd.service /etc/systemd/system/arkd.service
sudo systemctl daemon-reload

echo "==> Done! Next steps:"
echo "    1. Edit /etc/arkd/config.toml"
echo "    2. Copy arkd binary to /usr/local/bin/arkd"
echo "    3. sudo systemctl enable --now arkd"
