#!/bin/sh

SOCKET=./server.sock
DEVICE=/dev/ivshmem
MODDIR=~ghaf/shmsockproxy/module

pid=`ps | grep memsocket | grep -v grep`
result=$?
if [ result == 0 ]
then
  kill $(echo $pid | awk '{print $1}')
fi

if test -e "$SOCKET"; then
  echo "Removing $SOCKET"
  rm "$SOCKET"
fi

sudo rmmod kvm_ivshmem

if test ! -e "$DEVICE"; then
echo "Loading shared memory module"
sudo rmmod kvm_ivshmem ; sudo insmod $MODDIR/kvm_ivshmem.ko; sudo chmod a+rwx /dev/ivshmem
fi

./memsocket -s "$SOCKET" &
sleep 3
echo "Executing 'waypipe -d -s $SOCKET server -- firefox'"
waypipe -s "$SOCKET" server -- firefox
