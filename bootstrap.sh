#!/bin/sh

set -e

autoreconf --install --force --verbose
./configure
make
sudo make install