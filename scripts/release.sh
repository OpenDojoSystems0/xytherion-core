#!/usr/bin/env bash
# Usage: ./scripts/release.sh v0.4.1
# Builds linux/amd64 and linux/arm64 binaries, writes manifests, deploys to VPS.
# Requires (kept out of the repo on purpose — set them in your shell or a
# git-ignored .env):
#   XYTHERION_DEPLOY_HOST      user@host of the update server
#   XYTHERION_AGENT_BASE_URL   public URL where the binaries are served
#   XYTHERION_DEPLOY_KEY       SSH private key used for the upload
# Remote dir: /var/www/html/agent/

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>  (e.g. v0.4.1)"
  exit 1
fi

DEPLOY_HOST="${XYTHERION_DEPLOY_HOST:?set XYTHERION_DEPLOY_HOST (user@host)}"
BASE_URL="${XYTHERION_AGENT_BASE_URL:?set XYTHERION_AGENT_BASE_URL (https://…/agent)}"
DEPLOY_KEY="${XYTHERION_DEPLOY_KEY:?set XYTHERION_DEPLOY_KEY (path to the SSH key)}"
REMOTE_DIR="/var/www/html/agent"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

echo "→ Building $VERSION"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -ldflags="-s -w -X main.Version=$VERSION" \
  -o "$DIST/xytherion-agent-linux-amd64" \
  "$ROOT/cmd/xytherion"

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -trimpath -ldflags="-s -w -X main.Version=$VERSION" \
  -o "$DIST/xytherion-agent-linux-arm64" \
  "$ROOT/cmd/xytherion"

echo "→ Computing checksums"

SHA_AMD64=$(sha256sum "$DIST/xytherion-agent-linux-amd64" | awk '{print $1}')
SHA_ARM64=$(sha256sum "$DIST/xytherion-agent-linux-arm64" | awk '{print $1}')

# Manifests are signed: agents refuse unsigned or tampered ones.
SIGNING_KEY="${XYTHERION_SIGNING_KEY_FILE:-$HOME/.config/xytherion-signing/update.key}"
for ARCH in amd64 arm64; do
  if [ "$ARCH" = amd64 ]; then SHA="$SHA_AMD64"; else SHA="$SHA_ARM64"; fi
  URL="$BASE_URL/xytherion-agent-linux-$ARCH"
  SIG=$(cd "$ROOT" && go run ./scripts/signtool sign-manifest -key "$SIGNING_KEY" -version "$VERSION" -url "$URL" -sha "$SHA")
  printf '{"version":"%s","url":"%s","sha256":"%s","signature":"%s"}\n' "$VERSION" "$URL" "$SHA" "$SIG" > "$DIST/manifest-linux-$ARCH.json"
done

echo "  amd64: $SHA_AMD64"
echo "  arm64: $SHA_ARM64"

echo "→ Deploying to $DEPLOY_HOST:$REMOTE_DIR"

ssh -i "$DEPLOY_KEY" "$DEPLOY_HOST" "mkdir -p $REMOTE_DIR"
rsync -az --progress -e "ssh -i $DEPLOY_KEY" \
  "$DIST/xytherion-agent-linux-amd64" \
  "$DIST/xytherion-agent-linux-arm64" \
  "$DIST/manifest-linux-amd64.json" \
  "$DIST/manifest-linux-arm64.json" \
  "$DEPLOY_HOST:$REMOTE_DIR/"

echo "✓ Released $VERSION"
echo ""
echo "Set on each agent:"
echo "  export XYTHERION_UPDATE_URL=$BASE_URL/manifest-linux-amd64.json"
echo "  (or manifest-linux-arm64.json for ARM servers)"
