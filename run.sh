#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Quick Dashboard Launcher
# Repository: https://github.com/monkonthehill/NetSenital
# ==============================================================================

# Ensure binary is built
if [ ! -f "./netsentinel" ]; then
    echo "==> Building NetSentinel binary..."
    make build
fi

echo "==> Starting NetSentinel Web Control Dashboard..."
echo "==> Access URL: http://localhost:8000"

# web_app.py auto-elevates with sudo if not root
python3 web_app.py
