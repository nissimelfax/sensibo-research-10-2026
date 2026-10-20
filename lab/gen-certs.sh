#!/usr/bin/env bash
#
# gen-certs.sh — build a rogue CA + server certificate for the lab.
#
# Generates (locally, NOT committed):
#   rogue-ca.key / rogue-ca.crt   — the self-made Certificate Authority
#   server.key / server.crt       — the forged server cert, signed by the CA
#   server.pem                    — key + cert combined, for stunnel
#
# The forged cert mimics the original wildcard (CN=*.sensibo.com) and
# includes the local proxy IP in the SAN. All private keys are gitignored.
#
# Usage:  ./gen-certs.sh <LOCAL_PROXY_IP>
# Example:./gen-certs.sh 192.168.1.207
#
set -euo pipefail

LOCAL_IP="${1:-192.168.1.207}"
DAYS=3650

echo "[*] Local proxy IP for SAN: ${LOCAL_IP}"

# --- 1. Rogue CA ---
echo "[*] Generating rogue CA..."
openssl genrsa -out rogue-ca.key 2048
openssl req -x509 -new -nodes -key rogue-ca.key -sha256 -days ${DAYS} \
  -subj "/C=IL/O=Rogue Lab CA" \
  -out rogue-ca.crt

# --- 2. Server key + CSR ---
echo "[*] Generating server key and CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
  -subj "/C=US/ST=Some-State/O=Sensibo/CN=*.sensibo.com" \
  -out server.csr

# --- 3. SAN extension (modern clients check SAN, not CN) ---
cat > san.ext <<EOF
subjectAltName = DNS:*.sensibo.com, DNS:new-emq.sensibo.com, DNS:new-config.sensibo.com, IP:${LOCAL_IP}
EOF

# --- 4. Sign the server cert with the rogue CA ---
echo "[*] Signing server cert with rogue CA..."
openssl x509 -req -in server.csr \
  -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial \
  -out server.crt -days ${DAYS} -sha256 -extfile san.ext

# --- 5. Combine for stunnel ---
cat server.key server.crt > server.pem

echo "[+] Done."
echo "    server.pem  -> feed to stunnel"
echo "    (all .key / .crt / .pem are gitignored and will NOT be committed)"
