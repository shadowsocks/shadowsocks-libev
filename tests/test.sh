#!/bin/bash

result=0

function run_test {
    printf '\e[0;36m'
    echo "running test: $command $@"
    printf '\e[0m'

    $command "$@"
    status=$?
    if [ $status -ne 0 ]; then
        printf '\e[0;31m'
        echo "test failed: $command $@"
        printf '\e[0m'
        echo
        result=1
    else
        printf '\e[0;32m'
        echo OK
        printf '\e[0m'
        echo
    fi
    return 0
}

run_test python tests/test.py  -c tests/aes.json
run_test python tests/test.py  -c tests/aes-gcm.json
run_test python tests/test.py  -c tests/aes-ctr.json
run_test python tests/test.py  -c tests/rc4-md5.json
run_test python tests/test.py  -c tests/salsa20.json
run_test python tests/test.py  -c tests/chacha20.json
run_test python tests/test.py  -c tests/chacha20-ietf.json
run_test python tests/test.py  -c tests/chacha20-ietf-poly1305.json

exit $result
