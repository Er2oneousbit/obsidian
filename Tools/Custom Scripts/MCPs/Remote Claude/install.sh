#!/usr/bin/env bash
# ==============================================================================
#  Pentest MCP Server -- Install Script
#  Installs dependencies and prints Claude Code config snippet
#  Made with ❤️ from your friendly hacker - er2oneousbit
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PATH="$SCRIPT_DIR/server.py"

echo ""
echo "================================================"
echo "  Pentest MCP Server -- Installer"
echo "================================================"
echo ""

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install it first."
    exit 1
fi

echo "[*] Installing Python dependencies..."
pip3 install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages --quiet
echo "[+] Dependencies installed."

echo ""
echo "[*] Making server executable..."
chmod +x "$SERVER_PATH"
echo "[+] Done."

echo ""
echo "================================================"
echo "  Add this to your Claude Code config:"
echo "  (~/.claude/claude_desktop_config.json)"
echo "================================================"
echo ""
cat <<EOF
{
  "mcpServers": {
    "pentest": {
      "command": "python3",
      "args": ["$SERVER_PATH"]
    }
  }
}
EOF

echo ""
echo "  Or if you already have other MCP servers, just add"
echo "  the 'pentest' block inside your existing mcpServers."
echo ""
echo "================================================"
echo "  Quick test (run manually):"
echo "================================================"
echo ""
echo "  python3 $SERVER_PATH"
echo ""
echo "[+] Install complete. Restart Claude Code after updating config."
echo ""
