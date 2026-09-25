#!/bin/sh
# Helper for test/apple-jws-path.sc: one fresh EC P-256 hierarchy per case,
# written under $1/<case>/ as DER files the cell reads:
#   leaf.der  x5c[0]; leaf.key signs the JWS
#   i1.der    x5c[1] (carries the WWDR marker OID unless the case says not)
#   i2.der    x5c[2] where a case has a second intermediate (case pathlen)
#   root.der  x5c[last] and the root the cell pins
# Every file this script means to write is listed in $1/manifest; the cell
# checks each one exists, so a failed openssl step is a named failure and
# not a case that silently lost a certificate.
set -e
ISSUE_OPTS=""
d="$1"
rm -rf "$d"
mkdir -p "$d"
cd "$d"

LEAF_OID="1.2.840.113635.100.6.11.1"
WWDR_OID="1.2.840.113635.100.6.2.1"

key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
}

# root <dir>
root() {
  key "$1/root.key"
  printf '%s\n' '[req]' 'distinguished_name=dn' 'x509_extensions=ext' '[dn]' \
    '[ext]' 'basicConstraints=critical,CA:TRUE' 'keyUsage=critical,keyCertSign,cRLSign' \
    'subjectKeyIdentifier=hash' > "$1/root.cnf"
  openssl req -x509 -new -key "$1/root.key" -config "$1/root.cnf" \
    -subj "/CN=R15 Test Root $1" -days 30 -out "$1/root.pem" 2>/dev/null
  openssl x509 -in "$1/root.pem" -outform DER -out "$1/root.der"
}

# issue <dir> <name> <issuer-name> <extension lines...>
# extra openssl x509 options can be passed in the ISSUE_OPTS variable
issue() {
  dir="$1"; name="$2"; issuer="$3"; shift 3
  key "$dir/$name.key"
  openssl req -new -key "$dir/$name.key" -subj "/CN=R15 $name $dir" \
    -out "$dir/$name.csr" 2>/dev/null
  printf '[ext]\n' > "$dir/$name.ext"
  for line in "$@"; do printf '%s\n' "$line" >> "$dir/$name.ext"; done
  # shellcheck disable=SC2086
  openssl x509 -req -in "$dir/$name.csr" -CA "$dir/$issuer.pem" -CAkey "$dir/$issuer.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days 30 $ISSUE_OPTS \
    -extfile "$dir/$name.ext" -extensions ext -out "$dir/$name.pem" 2>/dev/null
  openssl x509 -in "$dir/$name.pem" -outform DER -out "$dir/$name.der"
}

CA_OK="basicConstraints=critical,CA:TRUE"
KU_CA="keyUsage=critical,keyCertSign,cRLSign"
WWDR="$WWDR_OID=ASN1:NULL"
LEAF_BC="basicConstraints=critical,CA:FALSE"
KU_LEAF="keyUsage=critical,digitalSignature"
LEAF_MARK="$LEAF_OID=ASN1:NULL"

# 1. valid: root -> marked CA -> marked leaf
mkdir valid; root valid
issue valid i1 root "$CA_OK" "$KU_CA" "$WWDR"
issue valid leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"

# 2. root -> CA(pathlen 0) -> marked CA -> leaf: the path is one CA too long
mkdir pathlen; root pathlen
issue pathlen i2 root "basicConstraints=critical,CA:TRUE,pathlen:0" "$KU_CA"
issue pathlen i1 i2 "$CA_OK" "$KU_CA" "$WWDR"
issue pathlen leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"

# 3. an extension nobody understands, on the intermediate: critical / not
mkdir critext; root critext
issue critext i1 root "$CA_OK" "$KU_CA" "$WWDR" "1.3.6.1.4.1.55555.1.1=critical,ASN1:NULL"
issue critext leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"
mkdir noncritext; root noncritext
issue noncritext i1 root "$CA_OK" "$KU_CA" "$WWDR" "1.3.6.1.4.1.55555.1.1=ASN1:NULL"
issue noncritext leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"

# 4. the leaf is issued by the ROOT; a marked CA is presented beside it but
#    no path goes through it
mkdir detour; root detour
issue detour i1 root "$CA_OK" "$KU_CA" "$WWDR"
issue detour leaf root "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"

# 6. the leaf's validity ended in the past
mkdir expired; root expired
issue expired i1 root "$CA_OK" "$KU_CA" "$WWDR"
# Set and cleared explicitly: in POSIX sh an assignment written in front of
# a FUNCTION call stays set afterwards, and every later case would be expired.
ISSUE_OPTS="-not_before 20200101000000Z -not_after 20210101000000Z"
issue expired leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"
ISSUE_OPTS=""

# 7. the intermediate requires an explicit policy and asserts one; the leaf
#    asserts none. The twin below is a separate hierarchy (its own keys,
#    names, serials). Of the extensions written here, the only difference is
#    the leaf's certificatePolicies; the key identifiers differ with the keys.
mkdir policy; root policy
issue policy i1 root "$CA_OK" "$KU_CA" "$WWDR" "policyConstraints=critical,requireExplicitPolicy:0" \
  "certificatePolicies=1.3.6.1.4.1.55555.2.1"
issue policy leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"
#    twin: the same constraint, and both certificates assert an arbitrary
#    policy -- what real certificates carry. Must still be accepted.
mkdir policyok; root policyok
issue policyok i1 root "$CA_OK" "$KU_CA" "$WWDR" "policyConstraints=critical,requireExplicitPolicy:0" \
  "certificatePolicies=1.3.6.1.4.1.55555.2.1"
issue policyok leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK" "certificatePolicies=1.3.6.1.4.1.55555.2.1"

# 8. the intermediate may sign certificates (keyUsage) but has NO
#    basicConstraints at all
mkdir nobc; root nobc
issue nobc i1 root "$KU_CA" "$WWDR"
issue nobc leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"

# 9. a valid FOUR-certificate chain: root -> CA -> marked CA -> leaf
mkdir valid4; root valid4
issue valid4 i2 root "$CA_OK" "$KU_CA"
issue valid4 i1 i2 "$CA_OK" "$KU_CA" "$WWDR"
issue valid4 leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"

# 10. the same shape, but i1 (marked) sits directly under the root and the
#     leaf is issued by i2 (unmarked): presented as [leaf, i1, i2, root], the
#     verified path is leaf -> i2 -> i1 -> root. Same length, different
#     certificate at position 1.
mkdir order; root order
issue order i1 root "$CA_OK" "$KU_CA" "$WWDR"
issue order i2 i1 "$CA_OK" "$KU_CA"
issue order leaf i2 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"

# 11. the leaf is not yet valid
mkdir future; root future
issue future i1 root "$CA_OK" "$KU_CA" "$WWDR"
ISSUE_OPTS="-not_before 20990101000000Z -not_after 20991231000000Z"
issue future leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"
ISSUE_OPTS=""

# 12. each Apple marker missing ALONE
mkdir noleafmark; root noleafmark
issue noleafmark i1 root "$CA_OK" "$KU_CA" "$WWDR"
issue noleafmark leaf i1 "$LEAF_BC" "$KU_LEAF"
mkdir nowwdr; root nowwdr
issue nowwdr i1 root "$CA_OK" "$KU_CA"
issue nowwdr leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"

# 13. name constraints on the intermediate: a leaf outside them / inside them
mkdir namebad; root namebad
issue namebad i1 root "$CA_OK" "$KU_CA" "$WWDR" "nameConstraints=critical,permitted;DNS:good.example"
issue namebad leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK" "subjectAltName=DNS:evil.example"
mkdir namegood; root namegood
issue namegood i1 root "$CA_OK" "$KU_CA" "$WWDR" "nameConstraints=critical,permitted;DNS:good.example"
issue namegood leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK" "subjectAltName=DNS:a.good.example"

# 14. what the deliberate non-strict profile must keep accepting:
#     basicConstraints CA:TRUE NOT marked critical (strict would refuse it)
mkdir bcnoncrit; root bcnoncrit
issue bcnoncrit i1 root "basicConstraints=CA:TRUE" "$KU_CA" "$WWDR"
issue bcnoncrit leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK"
#     and a leaf carrying an extendedKeyUsage (no purpose is set)
mkdir eku; root eku
issue eku i1 root "$CA_OK" "$KU_CA" "$WWDR"
issue eku leaf i1 "$LEAF_BC" "$KU_LEAF" "$LEAF_MARK" "extendedKeyUsage=clientAuth"

for c in valid pathlen critext noncritext detour expired policy policyok nobc \
         valid4 order future noleafmark nowwdr namebad namegood bcnoncrit eku; do
  for f in root.der i1.der leaf.der leaf.key; do echo "$c/$f"; done
done > manifest
for c in pathlen valid4 order; do echo "$c/i2.der"; done >> manifest
