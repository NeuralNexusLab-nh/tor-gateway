# syntax=docker/dockerfile:1.7

FROM alpine:3.20

RUN apk add --no-cache \
      tor \
      nginx \
      su-exec \
      ca-certificates \
    && mkdir -p \
      /var/lib/tor/data \
      /var/lib/tor/hs \
      /run/nginx \
      /var/lib/nginx/tmp \
    && chown -R tor:tor /var/lib/tor \
    && chown -R nginx:nginx /var/lib/nginx /run/nginx


# ============================================================
# Tor configuration
# ============================================================

RUN cat <<'TORRC' > /etc/tor/torrc
SocksPort 0

DataDirectory /var/lib/tor/data

HiddenServiceDir /var/lib/tor/hs
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8080

Log notice stdout
TORRC


# ============================================================
# Nginx configuration template
# ============================================================

RUN cat <<'NGINXCONF' > /etc/nginx/nginx.conf.template
user nginx;

worker_processes auto;

error_log /dev/stderr notice;
pid /run/nginx/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    server_tokens off;
    sendfile on;

    # Long Onion hostnames need a larger map hash bucket.
    map_hash_bucket_size 256;
    map_hash_max_size 2048;

    # Privacy-friendly access log.
    # Does not log query strings, cookies, UA, referer, etc.
    log_format privacy
        '$time_iso8601 $host "$request_method $uri" '
        '$status $body_bytes_sent';

    access_log /dev/stdout privacy;

    # Zeabur / Kubernetes internal DNS.
    resolver __RESOLVER__ valid=30s ipv6=off;
    resolver_timeout 5s;

    # WebSocket support.
    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }


    # ========================================================
    # Onion Host -> Upstream
    # ========================================================

    map $host $upstream {
        default "";

        # ----------------------------------------------------
        # Existing fixed routes
        # ----------------------------------------------------

        "__ONION__"              "__NXLABTW__";
        "www.__ONION__"          "__NXLABTW__";

        "astranote.__ONION__"    "__ASTRANOTE__";
        "nexacaptcha.__ONION__"  "__NEXACAPTCHA__";


        # ----------------------------------------------------
        # Dynamically generated routes
        #
        # Example env:
        #
        # SATORA_UPSTREAM=satora.zeabur.internal:8080
        #
        # Generates:
        #
        # "satora.<onion>"
        #     "satora.zeabur.internal:8080";
        # ----------------------------------------------------

        include /etc/nginx/onion-routes.conf;
    }


    # ========================================================
    # Onion HTTP server
    # ========================================================

    server {
        listen 8080 default_server;
        server_name _;


        # ----------------------------------------------------
        # Health endpoint
        # ----------------------------------------------------

        location = /_health {
            access_log off;
            default_type text/plain;
            return 200 "ok\n";
        }


        # ----------------------------------------------------
        # Reverse proxy
        # ----------------------------------------------------

        location / {
            # No matching Onion route.
            if ($upstream = "") {
                return 404;
            }

            proxy_http_version 1.1;

            # Preserve the Onion Host header.
            proxy_set_header Host $host;

            # Onion Services do not expose the user's real IP.
            proxy_set_header X-Real-IP 127.0.0.1;
            proxy_set_header X-Forwarded-For 127.0.0.1;

            proxy_set_header X-Forwarded-Proto http;
            proxy_set_header X-Forwarded-Host $host;

            # WebSockets
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;

            # Timeouts
            proxy_connect_timeout 10s;
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;

            client_max_body_size 100m;

            proxy_pass http://$upstream$request_uri;
        }
    }
}
NGINXCONF


# ============================================================
# Entrypoint
# ============================================================

RUN cat <<'ENTRYPOINT' > /usr/local/bin/entrypoint.sh
#!/bin/sh

set -eu
umask 077


# ============================================================
# Required environment variables
# ============================================================

: "${ONION_ADDRESS:?ONION_ADDRESS is required}"
: "${HS_SECRET_KEY_B64:?HS_SECRET_KEY_B64 is required}"
: "${HS_PUBLIC_KEY_B64:?HS_PUBLIC_KEY_B64 is required}"


# ============================================================
# Validate Onion v3 hostname
# ============================================================

if ! printf '%s\n' "$ONION_ADDRESS" \
    | grep -Eq '^[a-z2-7]{56}\.onion$'; then

    echo "[init] ERROR: invalid v3 onion hostname"
    exit 1
fi


# ============================================================
# Existing explicit upstreams
# ============================================================

NXLABTW_UPSTREAM="${NXLABTW_UPSTREAM:-nxlabtw.zeabur.internal:8080}"

ASTRANOTE_UPSTREAM="${ASTRANOTE_UPSTREAM:-astranote.zeabur.internal:8080}"

NEXACAPTCHA_UPSTREAM="${NEXACAPTCHA_UPSTREAM:-nexacaptcha.zeabur.internal:8080}"


# ============================================================
# Validate an upstream
#
# Allowed:
#
# hostname:port
#
# Examples:
#
# satora.zeabur.internal:8080
# api.zeabur.internal:3000
# 10.0.0.10:8080
#
# This deliberately does NOT allow:
#
# http://
# /
# ;
# spaces
# nginx syntax
#
# because these values are inserted into nginx.conf.
# ============================================================

validate_upstream() {
    VALUE="$1"

    if ! printf '%s\n' "$VALUE" \
        | grep -Eq '^[A-Za-z0-9.-]+:[0-9]{1,5}$'; then
        return 1
    fi

    PORT="${VALUE##*:}"

    if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        return 1
    fi

    return 0
}


# Validate the three built-in upstreams too.

for VALUE in \
    "$NXLABTW_UPSTREAM" \
    "$ASTRANOTE_UPSTREAM" \
    "$NEXACAPTCHA_UPSTREAM"
do
    if ! validate_upstream "$VALUE"; then
        echo "[init] ERROR: invalid built-in upstream: ${VALUE}"
        exit 1
    fi
done


# ============================================================
# Materialise Tor Onion Service identity
# ============================================================

HS_DIR="/var/lib/tor/hs"
DATA_DIR="/var/lib/tor/data"

echo "[init] materialising hidden-service keys"

mkdir -p \
    "$HS_DIR" \
    "$DATA_DIR"


printf '%s' "$HS_SECRET_KEY_B64" \
    | base64 -d \
    > "$HS_DIR/hs_ed25519_secret_key"


printf '%s' "$HS_PUBLIC_KEY_B64" \
    | base64 -d \
    > "$HS_DIR/hs_ed25519_public_key"


printf '%s\n' "$ONION_ADDRESS" \
    > "$HS_DIR/hostname"


# ============================================================
# Validate Tor key file sizes
# ============================================================

SECRET_SIZE="$(
    wc -c < "$HS_DIR/hs_ed25519_secret_key" \
    | tr -d '[:space:]'
)"

PUBLIC_SIZE="$(
    wc -c < "$HS_DIR/hs_ed25519_public_key" \
    | tr -d '[:space:]'
)"


if [ "$SECRET_SIZE" != "96" ]; then
    echo "[init] ERROR: bad secret key length: ${SECRET_SIZE}"
    exit 1
fi


if [ "$PUBLIC_SIZE" != "64" ]; then
    echo "[init] ERROR: bad public key length: ${PUBLIC_SIZE}"
    exit 1
fi


# ============================================================
# Tor permissions
# ============================================================

chown -R tor:tor /var/lib/tor

chmod 700 "$HS_DIR"
chmod 700 "$DATA_DIR"

chmod 600 "$HS_DIR/hs_ed25519_secret_key"
chmod 600 "$HS_DIR/hs_ed25519_public_key"
chmod 600 "$HS_DIR/hostname"


# ============================================================
# Nginx directories
# ============================================================

mkdir -p \
    /run/nginx \
    /var/lib/nginx/tmp

chown -R nginx:nginx \
    /var/lib/nginx \
    /run/nginx


# ============================================================
# Detect Zeabur / Kubernetes DNS resolver
# ============================================================

RESOLVER="$(
    awk '
        /^nameserver/ {
            print $2
            exit
        }
    ' /etc/resolv.conf
)"


if [ -z "$RESOLVER" ]; then
    RESOLVER="10.43.0.20"
fi


echo "[init] nginx resolver: ${RESOLVER}"
echo "[init] onion address: ${ONION_ADDRESS}"


# ============================================================
# Generate dynamic Onion routes from environment variables
# ============================================================

ROUTES_FILE="/etc/nginx/onion-routes.conf"
SEEN_FILE="/tmp/onion-routes-seen"

: > "$ROUTES_FILE"
: > "$SEEN_FILE"


echo "[routes] scanning *_UPSTREAM environment variables"


env | while IFS='=' read -r ENV_NAME ENV_VALUE
do
    # Environment variable matching is intentionally
    # case-insensitive.
    #
    # Examples:
    #
    # SATORA_UPSTREAM
    # satora_upstream
    # SaToRa_UpStReAm
    #
    # all become:
    #
    # satora

    LOWER_NAME="$(
        printf '%s' "$ENV_NAME" \
        | tr '[:upper:]' '[:lower:]'
    )"


    case "$LOWER_NAME" in
        *_upstream)

            SUBDOMAIN="${LOWER_NAME%_upstream}"


            # ------------------------------------------------
            # These routes already have explicit definitions.
            # Do not dynamically regenerate them.
            # ------------------------------------------------

            case "$SUBDOMAIN" in
                nxlabtw|www|astranote|nexacaptcha)
                    continue
                    ;;
            esac


            # ------------------------------------------------
            # Validate Onion subdomain
            # ------------------------------------------------

            if ! printf '%s\n' "$SUBDOMAIN" \
                | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'; then

                echo "[routes] SKIP invalid subdomain from ${ENV_NAME}: ${SUBDOMAIN}"
                continue
            fi


            # ------------------------------------------------
            # Reject duplicated route names
            #
            # Example:
            #
            # SATORA_UPSTREAM=...
            # satora_upstream=...
            #
            # Since matching is case-insensitive, these are
            # considered the same route.
            # ------------------------------------------------

            if grep -Fxq "$SUBDOMAIN" "$SEEN_FILE"; then
                echo "[routes] SKIP duplicate route: ${SUBDOMAIN}"
                continue
            fi


            # ------------------------------------------------
            # Validate upstream before writing it into Nginx
            # configuration.
            # ------------------------------------------------

            if ! validate_upstream "$ENV_VALUE"; then
                echo "[routes] SKIP invalid upstream for ${SUBDOMAIN}: ${ENV_VALUE}"
                continue
            fi


            printf '%s\n' "$SUBDOMAIN" >> "$SEEN_FILE"


            # ------------------------------------------------
            # Generate map entry
            # ------------------------------------------------

            printf '"%s.%s" "%s";\n' \
                "$SUBDOMAIN" \
                "$ONION_ADDRESS" \
                "$ENV_VALUE" \
                >> "$ROUTES_FILE"


            echo "[routes] ${SUBDOMAIN}.${ONION_ADDRESS} -> ${ENV_VALUE}"
            ;;

    esac
done


# ============================================================
# Show route count
# ============================================================

ROUTE_COUNT="$(
    wc -l < "$ROUTES_FILE" \
    | tr -d '[:space:]'
)"

echo "[routes] generated ${ROUTE_COUNT} dynamic Onion route(s)"


# ============================================================
# Generate final Nginx config
# ============================================================

sed \
    -e "s|__RESOLVER__|${RESOLVER}|g" \
    -e "s|__ONION__|${ONION_ADDRESS}|g" \
    -e "s|__NXLABTW__|${NXLABTW_UPSTREAM}|g" \
    -e "s|__ASTRANOTE__|${ASTRANOTE_UPSTREAM}|g" \
    -e "s|__NEXACAPTCHA__|${NEXACAPTCHA_UPSTREAM}|g" \
    /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf


# ============================================================
# Validate Nginx configuration
# ============================================================

echo "[init] validating nginx configuration"

nginx -t


# ============================================================
# Start Nginx
# ============================================================

echo "[init] starting nginx"

nginx


# ============================================================
# Start Tor
# ============================================================

echo "[init] starting Tor Onion Service"
echo "[init] onion address: ${ONION_ADDRESS}"

exec su-exec tor tor -f /etc/tor/torrc
ENTRYPOINT


RUN chmod 0755 /usr/local/bin/entrypoint.sh


EXPOSE 8080


# ============================================================
# Health check
# ============================================================

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=20s \
    --retries=3 \
    CMD pidof tor >/dev/null \
        && wget -q -O /dev/null http://127.0.0.1:8080/_health \
        || exit 1


CMD ["/usr/local/bin/entrypoint.sh"]
