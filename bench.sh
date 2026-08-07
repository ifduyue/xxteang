#!/bin/bash

PYTHON=${PYTHON-`which python`}

echo Benchmarking ...

echo -n "    encrypt: "
$PYTHON -mtimeit -s 'import xxteang' -s 'import os' -s 'key = os.urandom(16)' -s 'data = os.urandom(1000)' 'xxteang.encrypt(data, key)'

echo -n "    decrypt: "
$PYTHON -mtimeit -s 'import xxteang' -s 'import os' -s 'key = os.urandom(16)' -s 'data = xxteang.encrypt(os.urandom(1000), key)' 'xxteang.decrypt(data, key)'

echo -n "encrypt_hex: "
$PYTHON -mtimeit -s 'import xxteang' -s 'import os' -s 'key = os.urandom(16)' -s 'data = os.urandom(1000)' 'xxteang.encrypt_hex(data, key)'

echo -n "decrypt_hex: "
$PYTHON -mtimeit -s 'import xxteang' -s 'import os' -s 'key = os.urandom(16)' -s 'data = xxteang.encrypt_hex(os.urandom(1000), key)' 'xxteang.decrypt_hex(data, key)'
