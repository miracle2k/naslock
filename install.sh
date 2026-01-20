#!/usr/bin/env sh
set -eu

REPO="miracle2k/naslock"
BIN="naslock"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin) OS="darwin" ;;
  Linux) OS="linux" ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

case "${OS}-${ARCH}" in
  darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
  darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  *) echo "Unsupported platform: ${OS}-${ARCH}" >&2; exit 1 ;;
esac

ASSET="naslock-${TARGET}.tar.gz"
CHECKSUM="${ASSET}.sha256"

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
    return
  fi
  echo "curl or wget is required" >&2
  exit 1
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  echo "sha256sum or shasum is required" >&2
  exit 1
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fetch "${BASE_URL}/${ASSET}" "${TMP_DIR}/${ASSET}"
fetch "${BASE_URL}/${CHECKSUM}" "${TMP_DIR}/${CHECKSUM}"

EXPECTED="$(awk '{print $1}' "${TMP_DIR}/${CHECKSUM}")"
ACTUAL="$(hash_file "${TMP_DIR}/${ASSET}")"

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch for ${ASSET}" >&2
  exit 1
fi

tar -xzf "${TMP_DIR}/${ASSET}" -C "${TMP_DIR}"

if [ -n "${INSTALL_DIR:-}" ]; then
  DEST="$INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
  DEST="/usr/local/bin"
else
  DEST="$HOME/.local/bin"
fi

mkdir -p "$DEST"

if command -v install >/dev/null 2>&1; then
  install -m 755 "${TMP_DIR}/${BIN}" "${DEST}/${BIN}"
else
  cp "${TMP_DIR}/${BIN}" "${DEST}/${BIN}"
  chmod 755 "${DEST}/${BIN}"
fi

echo "Installed ${BIN} to ${DEST}/${BIN}"
case ":${PATH}:" in
  *":${DEST}:"*) ;;
  *) echo "Note: ${DEST} is not on your PATH." ;;
esac
