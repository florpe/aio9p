#!/usr/bin/env bash

set -euxo pipefail

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

PORT=8090
VERSION="9p2000"

do_test () {
    tmp="$(mktemp -d)"
    echo "Temp directory: $tmp"
    sudo mount -t 9p 127.0.0.1 "$tmp" -o trans=tcp,port="$PORT",version="$VERSION",uname=root

    ls -la "$tmp"

    echo -n foo | tee "$tmp/newfile" > /dev/null
    ls -la "$tmp"
    catres="$(cat "$tmp/newfile")"
    test "$catres" = "foo"

    echo -n foo | tee -a "$tmp/newfile" > /dev/null
    catres="$(cat "$tmp/newfile")"
    test "$catres" = "foofoo"


    sudo umount "$tmp"
    rm -r "$tmp"
}


main () {
    srvdmp="$(mktemp)"
    echo "Server dump file: $srvdmp"
    poetry run python3 -m aio9p.example.simple 2> "$srvdmp" &
    sleep 1
    do_test
    jobs -rp
    kill $(jobs -rp)
    rm "$srvdmp"
}

main
