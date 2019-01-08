#!/bin/bash
set -e -u -o pipefail

cat culper-server/Cargo.toml | sed -nr 's/version = "(.*)"/\1/p' > culper-server-version
cat culper/Cargo.toml | sed -nr 's/version = "(.*)"/\1/p' > culper-version
