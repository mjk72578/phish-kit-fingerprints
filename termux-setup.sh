#!/data/data/com.termux/files/usr/bin/bash
#
# ScamIntel — Termux bootstrap (Option 1: native packages)
#
# Installs precompiled aarch64 builds of OpenCV / NumPy / Pillow from
# Termux repos. No pip source builds. qr-fingerprint.py runs unmodified.
#
# If 'python-opencv' is not found, run `pkg search opencv` — repo naming
# drifts. tur-repo (github.com/termux-user-repository/tur) also carries
# OpenCV builds as a fallback source.
#
set -euo pipefail
echo "[*] Updating Termux package lists..."
pkg update -y
echo "[*] Installing native packages (python, opencv, numpy, pillow)..."
pkg install -y python python-opencv python-numpy python-pillow
echo "[*] Verifying imports..."
python3 - <<'EOF'
import cv2, numpy, PIL
print("cv2:   ", cv2.__version__)
print("numpy: ", numpy.__version__)
print("Pillow:", PIL.__version__)
EOF
echo "[*] Locking installed versions for reproducibility..."
pkg list-installed 2>/dev/null | grep -Ei "opencv|numpy|pillow|^python/" > termux-pkg-lock.txt || true
cat termux-pkg-lock.txt
echo "[+] Done. If anything breaks: restore qr-fingerprint.py from backup and start new."
