-include .env

.PHONY: deploy
deploy:; forge script DeployScript --rpc-url http://localhost:8545 --broadcast

.PHONY: docker_build
docker_build:; docker buildx build . -t dan13ram/wpokt-hyperlane-contracts:v0.0.1 --file ./docker/Dockerfile
