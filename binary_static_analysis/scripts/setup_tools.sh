#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${ROOT}/.tools"
DOWNLOAD_DIR="${TOOLS_DIR}/downloads"

mkdir -p "${DOWNLOAD_DIR}"

if [[ -n "${R2_BIN:-}" && -x "${R2_BIN}" ]] || command -v r2 >/dev/null 2>&1; then
  echo "radare2: using configured/system installation"
elif [[ -x "${TOOLS_DIR}/radare2/pkg/Payload/usr/local/bin/radare2" ]]; then
  echo "radare2: local installation already present"
elif [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  R2_PKG="${DOWNLOAD_DIR}/radare2-arm64-6.1.6.pkg"
  curl -L --fail --retry 3 \
    -o "${R2_PKG}" \
    "https://github.com/radareorg/radare2/releases/download/6.1.6/radare2-arm64-6.1.6.pkg"
  rm -rf "${TOOLS_DIR}/radare2"
  mkdir -p "${TOOLS_DIR}/radare2"
  pkgutil --expand-full "${R2_PKG}" "${TOOLS_DIR}/radare2/pkg"
  echo "radare2: installed locally"
else
  echo "radare2 not found. Install it or set R2_BIN." >&2
  exit 1
fi

if [[ -n "${GHIDRA_HEADLESS:-}" && -x "${GHIDRA_HEADLESS}" ]] || \
   command -v analyzeHeadless >/dev/null 2>&1; then
  echo "Ghidra: using configured/system installation"
elif [[ -x "${TOOLS_DIR}/ghidra_11.0.3_PUBLIC/support/analyzeHeadless" ]]; then
  echo "Ghidra: local installation already present"
else
  GHIDRA_ZIP="${DOWNLOAD_DIR}/ghidra_11.0.3_PUBLIC_20240410.zip"
  curl -L --fail --retry 3 -C - \
    -o "${GHIDRA_ZIP}" \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip"
  unzip -q "${GHIDRA_ZIP}" -d "${TOOLS_DIR}"
  echo "Ghidra: installed locally"
fi

