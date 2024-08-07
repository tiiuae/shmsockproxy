#!/usr/bin/env bash

set -euo pipefail
VERSION=v0.20.0
[[ ! -d thrift ]] && git clone https://github.com/apache/thrift.git --branch $VERSION --depth 1

pushd thrift
  git reset --hard $VERSION
  git clean -xdf

  cp -Rv ../thrift-shm/* .

  git add .
  git commit -m "thrift use shm sockets"
  git format-patch -k -1 -o ..
popd
