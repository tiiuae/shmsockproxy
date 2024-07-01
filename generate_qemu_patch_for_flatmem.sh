#!/usr/bin/env bash

set -euo pipefail

[[ ! -d qemu ]] && git clone https://github.com/qemu/qemu.git --branch v8.1.3 --depth 1

pushd qemu
  git reset --hard 179cc58e00eab7497ce0ac3a1897ec4878588a15
  git clean -xdf

  cp -Rv ../qemu-flatmem/contrib .
  cp -Rv ../qemu-flatmem/hw .
  cp -Rv ../qemu-flatmem/include .

  git add .
  git commit -m "ivshmem flat memory support"
  git format-patch -k -1 -o ..
popd
