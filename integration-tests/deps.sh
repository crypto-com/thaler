#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

PYTHON_VENV_DIR=${PYTHON_VENV_DIR:-".venv"}
if [ ! -d $PYTHON_VENV_DIR ];
then
    python3 -mvenv --without-pip $PYTHON_VENV_DIR
    source $PYTHON_VENV_DIR/bin/activate
    curl -sL https://bootstrap.pypa.io/get-pip.py | python
else
    source $PYTHON_VENV_DIR/bin/activate
fi
# FIXME use pypi2nix
pip3 install -r requirements.txt

pushd client-rpc; npm install; popd
