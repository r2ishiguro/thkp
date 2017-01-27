#!/bin/sh

TRILLIAN_ROOT=$GOPATH/src/github.com/google/trillian

TESTDATA=${TRILLIAN_ROOT}/testdata
RPC_PORT=36962
TEST_TREE_ID=6962
GT_PORT=6962

STARTUP_WAIT_SECONDS=10

function waitForServerStartup() {
  PORT=$1
  wget -q --spider --retry-connrefused --waitretry=1 -t ${STARTUP_WAIT_SECONDS} localhost:${PORT}
  # Wait a bit more to give it a chance to become actually available e.g. if Travis is slow
  sleep 2
}

$TRILLIAN_ROOT/trillian_log_server --private_key_password=towel --private_key_file=${TESTDATA}/log-rpc-server.privkey.pem --port ${RPC_PORT} --signer_interval="1s" --sequencer_sleep_between_runs="1s" --batch_size=100 &
waitForServerStartup ${RPC_PORT}

go run ./trillian_http.go --log_rpc_server="localhost:${RPC_PORT}" --port=${GT_PORT} --log_id=${TEST_TREE_ID}
waitForServerStartup ${GT_PORT}
