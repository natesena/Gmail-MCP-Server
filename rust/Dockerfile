# Gmail MCP server (Rust). Serves every account in the encrypted store over
# Streamable HTTP on 127.0.0.1:8080, meant to run inside a Tailscale
# sidecar's network namespace (see docker-compose.yml).
FROM rust:1.91-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin gmail-mcp

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 1000 gmail \
 && useradd -u 1000 -g 1000 -r -s /usr/sbin/nologin gmail \
 && mkdir /data && chown gmail:gmail /data && chmod 700 /data
COPY --from=build /src/target/release/gmail-mcp /usr/local/bin/gmail-mcp
USER gmail
ENV GMAIL_MCP_STORE=/data/store.json \
    GMAIL_MCP_STORE_KEY_FILE=/run/secrets/gmail_store_key \
    GMAIL_MCP_HTTP_ADDR=127.0.0.1:8080
VOLUME /data
CMD ["gmail-mcp", "serve"]
