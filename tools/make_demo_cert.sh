#!/bin/sh
# Makes a self-signed certificate for the demo (config/server.pem, config/server.key).
# Both are git-ignored. Clients need to skip verification (kdig +tls-ca= ..., or dig +tls without +tls-ca).
set -e
cd "$(dirname "$0")/.."
if [ -f config/server.pem ] && [ -f config/server.key ]; then
    echo "config/server.pem and config/server.key already exist"
    exit 0
fi
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
    -subj "/CN=encrypted-dns-resolver demo" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -keyout config/server.key -out config/server.pem
chmod 600 config/server.key
echo "wrote config/server.pem and config/server.key"
