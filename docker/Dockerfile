# Use the latest foundry image
FROM ghcr.io/foundry-rs/foundry as base

# Copy our source code into the container
WORKDIR /app
COPY . .

# Build and test the source code
RUN forge build
RUN forge test

RUN apk add --update --no-cache bash

ENV PORT ${PORT}
ENV CHAIN_ID ${CHAIN_ID}
ENV PRIVATE_KEY "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Run the application
CMD ["/app/docker/entrypoint.sh"]
