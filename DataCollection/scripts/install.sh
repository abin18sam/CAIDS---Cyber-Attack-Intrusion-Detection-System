#!/usr/bin/env bash
# CAIDS Data Collection - install helper
# Run as root after building (see README.md). Sets up the service user,
# directories, config, and systemd unit for 24/7 operation.
set -euo pipefail

BIN_SRC="build/caids_collector"
if [ ! -f "$BIN_SRC" ]; then
    echo "Build the project first: mkdir build && cd build && cmake .. && make -j" >&2
    exit 1
fi

id -u caids &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin caids

install -d -o caids -g caids /var/lib/caids/captures
install -d -o caids -g caids /var/log/caids
install -d /etc/caids

install -m 755 "$BIN_SRC" /usr/local/bin/caids_collector

if [ ! -f /etc/caids/collector.conf ]; then
    install -m 644 config/collector.conf /etc/caids/collector.conf
    echo "Wrote default config to /etc/caids/collector.conf - edit 'interface' before starting."
else
    echo "/etc/caids/collector.conf already exists, leaving it untouched."
fi

install -m 644 systemd/caids-data-collection.service /etc/systemd/system/caids-data-collection.service

systemctl daemon-reload
echo "Installed. Next steps:"
echo "  1) Edit /etc/caids/collector.conf (set 'interface')"
echo "  2) sudo systemctl enable --now caids-data-collection"
echo "  3) sudo systemctl status caids-data-collection"
echo "  4) tail -f /var/log/caids/collector.log"
