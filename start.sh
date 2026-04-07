#!/usr/bin/env bash

#  DNS Enumeration Tool – Launcher (macOS / Linux)
#  Run this script to start the web UI automatically.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "==============================================="
echo "  DNS Enumeration Tool - Launcher (MacOS/Linux)"
echo "==============================================="
echo ""

# Detect Python 3
if command -v python3 &>/dev/null; then
    PY=python3
elif command -v python &>/dev/null; then
    PY=python
else
    echo "[!] Python 3 is not installed. Please install it from https://python.org"
    exit 1
fi

echo "[*] Using Python: $($PY --version)"

# Create a virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    $PY -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install / upgrade dependencies
echo "[*] Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo ""
echo "[*] Starting DNS Enumeration Tool Web UI..."
echo "[*] Open http://127.0.0.1:5000 in your browser"
echo "[*] Press Ctrl+C to stop"
echo ""

python frontend/app.py
