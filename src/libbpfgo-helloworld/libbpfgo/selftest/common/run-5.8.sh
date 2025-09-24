#!/bin/bash

# SETTINGS

TEST=$(dirname $0)/$1
TIMEOUT=5

# COMMON

COMMON="$(dirname $0)/../common/common.sh"
[[ -f $COMMON ]] && { . $COMMON; } || { error "no common"; exit 1; }

# MAIN

kern_version ge 5.8

check_build
check_ppid
test_exec
test_finish

exit 0
