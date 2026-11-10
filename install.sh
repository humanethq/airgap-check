#!/usr/bin/env sh
set -eu

REPO="humanethq/airgap-check"
VERSION="${AIRGAP_CHECK_VERSION:-v0.2.2}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "$OS" in
  darwin|linux) ;;
  *)
    echo "Unsupported OS: $OS (use Windows zip from GitHub Releases or 'go install')" >&2
    exit 1
    ;;
esac

TARBALL="airgap-check_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading airgap-check (${VERSION}) for ${OS}/${ARCH}..."
curl -fsSL "$URL" -o "${TMP_DIR}/${TARBALL}"
tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"

INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

install -m 0755 "${TMP_DIR}/airgap-check" "${INSTALL_DIR}/airgap-check"
echo "Installed airgap-check to ${INSTALL_DIR}/airgap-check"
"${INSTALL_DIR}/airgap-check" --version
