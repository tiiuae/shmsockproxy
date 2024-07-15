#!/usr/bin/env bash

set -euo pipefail

[[ ! -d qemu ]] && git clone https://github.com/qemu/qemu.git --branch v9.0.0 --depth 1

pushd qemu
  git reset --hard c25df57ae8f9fe1c72eee2dab37d76d904ac382e
  git clean -xdf

  cp -Rv ../qemu-flatmem/contrib .
  cp -Rv ../qemu-flatmem/hw .
  cp -Rv ../qemu-flatmem/include .

  git add .
  git commit -m "ivshmem flat memory support"
  git format-patch -k -1 -o ..
popd
