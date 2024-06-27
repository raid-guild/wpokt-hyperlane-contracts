-include .env

.PHONY: deploy
deploy:; forge script LocalDeployScript --rpc-url http://localhost:8545 --broadcast

.PHONY: deploy_testnet
deploy_testnet:; forge script TestnetDeployScript --rpc-url ${network} --private-key ${PRIVATE_KEY} --verify --broadcast

.PHONY: docker_build
docker_build:; docker buildx build . -t dan13ram/wpokt-hyperlane-contracts:v0.0.1 --file ./docker/Dockerfile
