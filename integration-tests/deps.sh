#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

pushd bot;
PYTHON_VENV_DIR=${PYTHON_VENV_DIR:-".venv"}
if [ ! -d $PYTHON_VENV_DIR ];
then
    python3 -mvenv --without-pip $PYTHON_VENV_DIR
    source $PYTHON_VENV_DIR/bin/activate
    curl -sL https://bootstrap.pypa.io/get-pip.py | python
else
    source $PYTHON_VENV_DIR/bin/activate
fi
pip3 install -e .
pip3 install supervisor pytest iso8601
popd

pushd client-rpc; npm install; popd
