#!/bin/bash

set -m

anvil --mnemonic 'test test test test test test test test test test test junk' --host 0.0.0.0 --block-time 1 &

sleep 5

forge script /app/script/Deploy.s.sol:Deploy --rpc-url "http://127.0.0.1:8545" --private-key "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" --broadcast

fg %1
