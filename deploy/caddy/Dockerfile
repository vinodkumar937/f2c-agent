# f2c-caddy: stock Caddy 2.11.7 plus the caddy-dns/digitalocean, caddy-dns/cloudflare and caddy-dns/acmedns DNS providers, used for
# DNS-01 wildcard certificates (the engine's base-domain wildcard and per-server wildcards).
# Tag: f2c-caddy:2.11.7-do1-cf1-ad1 (keep in sync with F2C_CADDY_TAG in deploy/install.sh and the pins in
# .github/workflows/caddy-binaries.yml). caddy-dns/digitalocean has no release tags, so it is pinned to a commit (2025-06-06);
# caddy-dns/cloudflare is pinned to release v0.2.4; caddy-dns/acmedns ("Other" provider) to release v0.7.0.
FROM caddy:2.11.7-builder AS builder
RUN xcaddy build v2.11.7 \
    --with github.com/caddy-dns/digitalocean@04bde2867106aa1b44c2f9da41a285fa02e629c5 \
    --with github.com/caddy-dns/cloudflare@v0.2.4 \
    --with github.com/caddy-dns/acmedns@v0.7.0

FROM caddy:2.11.7
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
