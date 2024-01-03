#!/bin/sh

SOCKET=./client.sock
DEVICE=/dev/ivshmem
MODDIR=~ghaf/shmsockproxy/module

pid=`ps | grep memsocket | awk '{print $1}'`
result=$?
if [ $result == 0 ]; then
  kill $pid
fi

if test -e $SOCKET; then
  echo "Removing $SOCKET"
  rm "$SOCKET"
fi

sudo rmmod kvm_ivshmem
if test ! -e "$DEVICE"; then
echo "Loading shared memory module"
sudo rmmod kvm_ivshmem ; sudo insmod $MODDIR/kvm_ivshmem.ko; sudo chmod a+rwx /dev/ivshmem
fi

./memsocket -c "$SOCKET" &
echo "Starting waypipe"
waypipe  -s "$SOCKET" client
