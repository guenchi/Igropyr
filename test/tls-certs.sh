#!/bin/sh
# Helper for test/tls.sc: ephemeral test PKI in $1.
#   ca.pem            test CA (the trust anchor the client is given)
#   good.pem/.key     leaf signed by ca, SAN DNS:localhost,IP:127.0.0.1
#   wrong.pem/.key    leaf signed by ca, SAN DNS:wrong.example (mismatch case)
#   self.pem/.key     self-signed, SAN IP:127.0.0.1 (untrusted-chain case)
#   inter.*, chained-*  a chain with an intermediate (see below)
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

# ---- a chain with an intermediate (test/tls-listener.sc, H7′) -------------
#   inter.pem/.key       intermediate CA signed by ca (CA:TRUE, pathlen 0)
#   chained.key          leaf key signed by inter, SAN DNS:localhost,IP:127.0.0.1
#   chained-full.pem     leaf + inter (what a correctly configured listener serves)
#   chained-leaf.pem     leaf only (the "missing intermediate" misconfiguration)
# A client trusting ca.pem alone verifies chained-full and refuses chained-leaf
# with an issuer error -- not a hostname, expiry or self-signed one.
openssl req -newkey rsa:2048 -nodes -keyout inter.key -out inter.csr \
  -subj "/CN=igropyr-test-inter" 2>/dev/null
printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > inter.ext
openssl x509 -req -in inter.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 2 -extfile inter.ext -out inter.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout chained.key -out chained.csr \
  -subj "/CN=chained" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n" > chained.ext
openssl x509 -req -in chained.csr -CA inter.pem -CAkey inter.key -CAcreateserial \
  -days 2 -extfile chained.ext -out chained-leaf.pem 2>/dev/null
cat chained-leaf.pem inter.pem > chained-full.pem

echo "certs ready in $d"
