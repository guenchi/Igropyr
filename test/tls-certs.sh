#!/bin/bash
# Helper for test/tls.sc: ephemeral test PKI in $1.
#   ca.pem            test CA (the trust anchor the client is given)
#   good.pem/.key     leaf signed by ca, SAN DNS:localhost,IP:127.0.0.1
#   wrong.pem/.key    leaf signed by ca, SAN DNS:wrong.example (mismatch case)
#   self.pem/.key     self-signed, SAN IP:127.0.0.1 (untrusted-chain case)
set -e
d="$1"
rm -rf "$d"
mkdir -p "$d"
cd "$d"

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 2 -subj "/CN=igropyr-test-ca" 2>/dev/null

leaf() { # name san
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" \
    -subj "/CN=$1" 2>/dev/null
  printf "subjectAltName=%s\n" "$2" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 2 -extfile "$1.ext" -out "$1.pem" 2>/dev/null
}
leaf good  "DNS:localhost,IP:127.0.0.1"
leaf wrong "DNS:wrong.example"

openssl req -x509 -newkey rsa:2048 -nodes -keyout self.key -out self.pem \
  -days 2 -subj "/CN=self" -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null

echo "certs ready in $d"
