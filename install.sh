#!/usr/bin/env bash
set -euo pipefail

REPO="OpenDojoSystems0/xytherion-core"
BINARY="xytherion"
INSTALL_DIR="/usr/local/bin"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}Xytherion — Installation${NC}"
echo "────────────────────────────────────"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo -e "${RED}Architecture non supportée: $ARCH${NC}"
    exit 1
    ;;
esac

case "$OS" in
  darwin|linux) ;;
  *)
    echo -e "${RED}Système non supporté: $OS${NC}"
    exit 1
    ;;
esac

echo -e "Système détecté : ${BLUE}${OS}/${ARCH}${NC}"

# Get latest release
echo "Récupération de la dernière version..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
  echo -e "${RED}Impossible de récupérer la dernière version.${NC}"
  exit 1
fi

# Sanitize version tag — must match vX.Y.Z
if ! echo "$LATEST" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo -e "${RED}Tag de version invalide: ${LATEST}${NC}"
  exit 1
fi

echo -e "Version : ${BLUE}${LATEST}${NC}"

# Download binary and checksum
ASSET="${BINARY}-${OS}-${ARCH}"
BASE="https://github.com/${REPO}/releases/download/${LATEST}"
URL="${BASE}/${ASSET}"
TMP=$(mktemp)
TMP_SUM=$(mktemp)
trap 'rm -f "$TMP" "$TMP_SUM"' EXIT

echo "Téléchargement..."
curl -fsSL "$URL" -o "$TMP"

# Verify SHA256 against the release's checksums.txt — mandatory.
if ! curl -fsSL "${BASE}/checksums.txt" -o "$TMP_SUM"; then
  echo -e "${RED}checksums.txt introuvable pour ${LATEST} — installation annulée par sécurité.${NC}"
  exit 1
fi
EXPECTED=$(awk -v f="$ASSET" '$2 == f || $2 == "*"f {print $1}' "$TMP_SUM")
if [ -z "$EXPECTED" ]; then
  echo -e "${RED}Aucune empreinte SHA256 pour ${ASSET} — installation annulée.${NC}"
  exit 1
fi
if command -v sha256sum &>/dev/null; then
  ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  ACTUAL=$(shasum -a 256 "$TMP" | awk '{print $1}')
else
  echo -e "${RED}sha256sum/shasum introuvable — impossible de vérifier l'intégrité.${NC}"
  rm -f "$TMP" "$TMP_SUM"
  exit 1
fi
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo -e "${RED}Vérification SHA256 échouée — téléchargement corrompu ou altéré.${NC}"
  rm -f "$TMP" "$TMP_SUM"
  exit 1
fi
echo -e "${GREEN}✓ SHA256 vérifié${NC}"

chmod 755 "$TMP"

# Install
# The binary must belong to root: the Linux service runs as root, so a binary
# owned by the installing user would let that user become root.
if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$TMP" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installation dans ${INSTALL_DIR} (sudo requis)..."
  sudo install -m 0755 -o root "$TMP" "${INSTALL_DIR}/${BINARY}"
fi

echo ""
echo -e "${GREEN}✓ Xytherion ${LATEST} installé avec succès${NC}"
echo ""

# Ask about autostart
echo "Voulez-vous que l'agent démarre automatiquement au démarrage du système ?"
echo -e "  ${BOLD}[o]${NC} Oui, lancer au boot (recommandé pour un serveur)"
echo -e "  ${BOLD}[n]${NC} Non, je le lancerai manuellement"
echo ""
# With `curl … | bash`, stdin is the script itself: ask on the terminal instead.
# Non-interactive installs can set XYTHERION_AUTOSTART=o|n.
AUTOSTART_CHOICE="${XYTHERION_AUTOSTART:-}"
if [ -z "$AUTOSTART_CHOICE" ]; then
  if [ -r /dev/tty ]; then
    read -rp "Votre choix [o/n] : " AUTOSTART_CHOICE < /dev/tty || AUTOSTART_CHOICE="n"
  else
    AUTOSTART_CHOICE="n"
  fi
fi

case "$AUTOSTART_CHOICE" in
  o|O|oui|yes|y|Y)
    if [ "$OS" = "darwin" ]; then
      PLIST="$HOME/Library/LaunchAgents/com.xytherion.agent.plist"
      mkdir -p "$HOME/.xytherion" "$HOME/Library/LaunchAgents"
      launchctl unload "$PLIST" 2>/dev/null || true
      cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.xytherion.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/${BINARY}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>XYTHERION_DATA_FILE</key>
    <string>$HOME/.xytherion/data.json</string>
  </dict>
  <key>WorkingDirectory</key>
  <string>$HOME/.xytherion</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$HOME/.xytherion/agent.log</string>
  <key>StandardErrorPath</key>
  <string>$HOME/.xytherion/agent.log</string>
</dict>
</plist>
EOF
      launchctl load "$PLIST" 2>/dev/null || true
      echo -e "${GREEN}✓ Agent configuré pour démarrer au login (launchd)${NC}"
      echo -e "  Logs : ${BLUE}~/.xytherion/agent.log${NC}"
      echo -e "  Arrêter : ${BOLD}launchctl unload ~/Library/LaunchAgents/com.xytherion.agent.plist${NC}"

    elif [ "$OS" = "linux" ]; then
      SERVICE="/etc/systemd/system/xytherion.service"
      # A server is usually viewed from another machine: protect the API with a
      # token (kept on reinstall). Readable by root only.
      ENV_FILE="/etc/xytherion/agent.env"
      if ! sudo test -f "$ENV_FILE"; then
        TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
        sudo install -d -m 0700 /etc/xytherion
        echo "XYTHERION_TOKEN=${TOKEN}" | sudo tee "$ENV_FILE" > /dev/null
        sudo chmod 0600 "$ENV_FILE"
        NEW_TOKEN="$TOKEN"
      fi
      sudo tee "$SERVICE" > /dev/null <<EOF
[Unit]
Description=Xytherion monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${INSTALL_DIR}/${BINARY}
EnvironmentFile=/etc/xytherion/agent.env
Environment=XYTHERION_DATA_FILE=/var/lib/xytherion/data.json
StateDirectory=xytherion
StateDirectoryMode=0700
WorkingDirectory=/var/lib/xytherion
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}
PrivateDevices=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
      sudo systemctl daemon-reload
      sudo systemctl enable xytherion
      sudo systemctl restart xytherion
      echo -e "${GREEN}✓ Agent configuré pour démarrer au boot (systemd)${NC}"
      if [ -n "${NEW_TOKEN:-}" ]; then
        echo ""
        echo -e "${BOLD}Jeton d'accès du dashboard${NC} (à conserver, affiché une seule fois) :"
        echo -e "  ${BLUE}${NEW_TOKEN}${NC}"
        echo -e "  Ouvrez http://IP-du-serveur:9001 et collez-le dans « Jeton d'accès »."
        echo -e "  Il est stocké dans ${ENV_FILE} (root uniquement)."
      fi
      echo -e "  Statut : ${BOLD}systemctl status xytherion${NC}"
      echo -e "  Arrêter : ${BOLD}sudo systemctl stop xytherion${NC}"
    fi
    ;;
  *)
    echo -e "  Pas de démarrage automatique configuré."
    echo ""
    echo "Pour démarrer l'agent manuellement :"
    echo -e "  ${BOLD}xytherion${NC}"
    ;;
esac

echo ""
echo -e "Agent disponible sur : ${BLUE}http://localhost:9001${NC}"
