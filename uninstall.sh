#!/usr/bin/env bash
set -euo pipefail

BINARY="xytherion"
INSTALL_DIR="/usr/local/bin"
PLIST="$HOME/Library/LaunchAgents/com.xytherion.agent.plist"
SYSTEMD_SERVICE="/etc/systemd/system/xytherion.service"
DATA_DIR="$HOME/.xytherion"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

echo -e "${BOLD}Xytherion — Désinstallation${NC}"
echo "────────────────────────────────────"
echo ""

# Stop and remove autostart
if [ "$OS" = "darwin" ] && [ -f "$PLIST" ]; then
  echo "Arrêt du service launchd..."
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  echo -e "${GREEN}✓ Service launchd supprimé${NC}"

elif [ "$OS" = "linux" ] && [ -f "$SYSTEMD_SERVICE" ]; then
  echo "Arrêt du service systemd..."
  sudo systemctl disable --now xytherion 2>/dev/null || true
  sudo rm -f "$SYSTEMD_SERVICE"
  sudo systemctl daemon-reload
  echo -e "${GREEN}✓ Service systemd supprimé${NC}"
else
  echo -e "  Aucun service de démarrage automatique détecté."
fi

# Kill running agent if any
if pgrep -x "$BINARY" > /dev/null 2>&1; then
  echo "Arrêt de l'agent en cours d'exécution..."
  pkill -x "$BINARY" || true
  echo -e "${GREEN}✓ Agent arrêté${NC}"
fi

# Remove binary
if [ -f "${INSTALL_DIR}/${BINARY}" ]; then
  if [ -w "$INSTALL_DIR" ]; then
    rm -f "${INSTALL_DIR}/${BINARY}"
  else
    sudo rm -f "${INSTALL_DIR}/${BINARY}"
  fi
  echo -e "${GREEN}✓ Binaire supprimé${NC}"
else
  echo -e "  Binaire non trouvé dans ${INSTALL_DIR}."
fi

# Ask about data directories (~/.xytherion, and /var/lib/xytherion for the Linux service)
SYSTEM_DATA_DIR="/var/lib/xytherion"
echo ""
if [ -d "$DATA_DIR" ] || [ -d "$SYSTEM_DATA_DIR" ]; then
  [ -d "$DATA_DIR" ] && echo -e "${YELLOW}Données utilisateur : ${DATA_DIR}${NC}"
  [ -d "$SYSTEM_DATA_DIR" ] && echo -e "${YELLOW}Données du service : ${SYSTEM_DATA_DIR}${NC}"
  echo "  Elles contiennent les logs, moniteurs et webhooks de l'agent."
  echo ""
  # Read from the terminal so this also works with `curl … | bash`.
  REMOVE_DATA="${XYTHERION_REMOVE_DATA:-}"
  if [ -z "$REMOVE_DATA" ] && [ -r /dev/tty ]; then
    read -rp "Supprimer également ces données ? [o/n] : " REMOVE_DATA < /dev/tty || REMOVE_DATA="n"
  fi
  case "$REMOVE_DATA" in
    o|O|oui|yes|y|Y)
      rm -rf "$DATA_DIR"
      if [ -d "$SYSTEM_DATA_DIR" ]; then sudo rm -rf "$SYSTEM_DATA_DIR"; fi
      if [ -d /etc/xytherion ]; then sudo rm -rf /etc/xytherion; fi
      echo -e "${GREEN}✓ Données supprimées${NC}"
      ;;
    *)
      echo -e "  Données conservées dans ${DATA_DIR}."
      ;;
  esac
fi

echo ""
echo -e "${GREEN}✓ Xytherion désinstallé avec succès.${NC}"
