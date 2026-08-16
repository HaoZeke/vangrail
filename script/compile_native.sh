#!/usr/bin/env bash
# Build the optional Magnus kernel (hashed bag + linear dot product).
# The vangrail gem itself does not need this.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${GEM_HOME:-}" ]; then
  default="$(ruby -rrubygems -e 'print Gem.default_dir')"
  export GEM_PATH="${GEM_HOME}${GEM_PATH:+:$GEM_PATH}:$default"
fi
cd "$root/ext/vangrail_native"
ruby extconf.rb
make
# rb-sys drops the cdylib next to the crate; put it on RUBYLIB.
if [ -f vangrail_native.so ]; then
  mkdir -p "$root/lib"
  cp -f vangrail_native.so "$root/lib/vangrail_native.so"
fi
echo "native kernel: $root/lib/vangrail_native.so"
