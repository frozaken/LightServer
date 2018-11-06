#!/bin/sh
# pilauncher.sh

export PYTHONPATH=~/.local/lib/python3.5/site-packages
echo "Pythonpath: $PYTHONPATH"
cd ~/repos/LightServer
./miniserver.py
cd /
