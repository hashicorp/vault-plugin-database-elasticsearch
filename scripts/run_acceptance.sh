#!/usr/bin/env bash
set -ex

make dev

vault server \
  -log-level=debug \
  -dev \
  -dev-ha -dev-transactional -dev-root-token-id=root -dev-plugin-dir=$PWD/bin &
VAULT_PID=$!
sleep 2

function cleanup {
  echo ""
  echo "==> Cleaning up"
  kill -INT "$VAULT_PID"
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

export VAULT_ACC=1
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root

## uncomment these to run against a real elasticsearch
# export ES_URL=https://localhost:9200
# export ES_USERNAME=vault
# export ES_PASSWORD=myPa55word
# export CA_CERT=$PWD/scripts/certs/ca/ca.crt
# export CLIENT_CERT=$PWD/scripts/certs/es01/es01.crt
# export CLIENT_KEY=$PWD/scripts/certs/es01/es01.key

go test -v ./... -run Test_Acceptance
