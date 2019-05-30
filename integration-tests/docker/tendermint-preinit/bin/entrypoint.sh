#!/usr/bin/env bash

if [ "x${FEE_SCHEMA}" = "xZERO_FEE" ] ; then
  echo "[Config] Fee Schema: Zero Fee"
  cp -r config-template/zerofee/* config/
else
  echo "[Config] Fee Schema: With Fee"
  cp -r config-template/fee/* config/
fi
echo "/usr/bin/tendermint node --proxy_app=${PROXY_APP}"
/usr/bin/tendermint node --proxy_app=${PROXY_APP}
