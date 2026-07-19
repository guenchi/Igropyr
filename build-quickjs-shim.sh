#!/usr/bin/env bash
# Build libigropyr-quickjs (the C shim for (igropyr quickjs)).
# Requires the QuickJS library + headers:
#   macOS: brew install quickjs
#   Linux: quickjs from distro or source (expects quickjs/quickjs.h + libquickjs)
set -euo pipefail
cd "$(dirname "$0")"

if [ "$(uname)" = "Darwin" ]; then
  QJS_PREFIX="${QJS_PREFIX:-$(brew --prefix quickjs)}"
  cc -O2 -shared -fPIC c/quickjs-shim.c \
    -I"${QJS_PREFIX}/include" \
    -L"${QJS_PREFIX}/lib/quickjs" -lquickjs \
    -o libigropyr-quickjs.dylib
  echo "built libigropyr-quickjs.dylib"
else
  cc -O2 -shared -fPIC c/quickjs-shim.c \
    ${QJS_CFLAGS:-} ${QJS_LDFLAGS:--lquickjs} -lpthread -lm \
    -o libigropyr-quickjs.so
  echo "built libigropyr-quickjs.so"
fi
