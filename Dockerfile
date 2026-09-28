# syntax=docker/dockerfile:1.7

FROM alpine:3.20


# ============================================================
# Packages / directories
# ============================================================

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

    # Onion hostname 很長，避免 nginx map hash bucket 不夠大
    map_hash_bucket_size 256;
    map_hash_max_size 2048;


    # --------------------------------------------------------
    # Privacy-friendly access log
    #
    # 不記：
    # - query string
    # - cookies
    # - user-agent
    # - referer
    #
    # 避免 reset token / auth token 被丟進 logs。
    # --------------------------------------------------------

    log_format privacy
        '$time_iso8601 $host "$request_method $uri" '
        '$status $body_bytes_sent';

    access_log /dev/stdout privacy;


    # --------------------------------------------------------
    # Kubernetes / Zeabur internal DNS resolver
    # --------------------------------------------------------

    resolver __RESOLVER__ valid=30s ipv6=off;


    # --------------------------------------------------------
    # WebSocket support
    # --------------------------------------------------------

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }


    # --------------------------------------------------------
    # Onion virtual host routing
    # --------------------------------------------------------

    map $host $upstream {
        default "";

        # NXLabTW root
        "__ONION__"              "__NXLABTW__";
        "www.__ONION__"          "__NXLABTW__";

        # NexaCAPTCHA
        "nexacaptcha.__ONION__"  "__NEXACAPTCHA__";

        # AstraNote
        "astranote.__ONION__"    "__ASTRANOTE__";
    }


    # ========================================================
    # Main reverse proxy
    # ========================================================

    server {
        listen 8080 default_server;
        server_name _;


        # ----------------------------------------------------
        # Health check
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

            # Unknown Host → 404
            if ($upstream = "") {
                return 404;
            }

            proxy_http_version 1.1;


            # ------------------------------------------------
            # Headers
            # ------------------------------------------------

            proxy_set_header Host $host;

            # Tor Onion Service 不會提供訪客原始 IP
            proxy_set_header X-Real-IP 127.0.0.1;
            proxy_set_header X-Forwarded-For 127.0.0.1;

            proxy_set_header X-Forwarded-Proto http;
            proxy_set_header X-Forwarded-Host $host;


            # ------------------------------------------------
            # WebSocket
            # ------------------------------------------------

            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;


            # ------------------------------------------------
            # Timeouts
            # ------------------------------------------------

            proxy_connect_timeout 30s;
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;


            # ------------------------------------------------
            # Upload size
            # ------------------------------------------------

            client_max_body_size 100m;


            # ------------------------------------------------
            # Dynamic Zeabur internal upstream
            # ------------------------------------------------

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

# 新建立的敏感檔案預設只有 owner 可讀寫
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
# Upstreams
# ============================================================

NXLABTW_UPSTREAM="${NXLABTW_UPSTREAM:-nxlabtw.zeabur.internal:8080}"

NEXACAPTCHA_UPSTREAM="${NEXACAPTCHA_UPSTREAM:-nexacaptcha.zeabur.internal:8080}"

ASTRANOTE_UPSTREAM="${ASTRANOTE_UPSTREAM:-astranote.zeabur.internal:8080}"


# ============================================================
# Tor Hidden Service keys
# ============================================================

HS_DIR="/var/lib/tor/hs"
DATA_DIR="/var/lib/tor/data"

echo "[init] materialising hidden-service keys"

mkdir -p "$HS_DIR" "$DATA_DIR"


# Secret key
printf '%s' "$HS_SECRET_KEY_B64" \
    | base64 -d \
    > "$HS_DIR/hs_ed25519_secret_key"


# Public key
printf '%s' "$HS_PUBLIC_KEY_B64" \
    | base64 -d \
    > "$HS_DIR/hs_ed25519_public_key"


# Hostname
printf '%s\n' "$ONION_ADDRESS" \
    > "$HS_DIR/hostname"


# ============================================================
# Validate key sizes
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
# Nginx permissions
# ============================================================

mkdir -p \
    /run/nginx \
    /var/lib/nginx/tmp

chown -R nginx:nginx \
    /var/lib/nginx \
    /run/nginx


# ============================================================
# Detect DNS resolver
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


# ============================================================
# Generate nginx.conf
# ============================================================

sed \
    -e "s|__RESOLVER__|${RESOLVER}|g" \
    -e "s|__ONION__|${ONION_ADDRESS}|g" \
    -e "s|__NXLABTW__|${NXLABTW_UPSTREAM}|g" \
    -e "s|__NEXACAPTCHA__|${NEXACAPTCHA_UPSTREAM}|g" \
    -e "s|__ASTRANOTE__|${ASTRANOTE_UPSTREAM}|g" \
    /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf


# ============================================================
# Validate nginx
# ============================================================

echo "[init] validating nginx configuration"

nginx -t


# ============================================================
# Start nginx
# ============================================================

echo "[init] starting nginx"

nginx


# ============================================================
# Start Tor
# ============================================================

echo "[init] starting Tor hidden service"
echo "[init] onion address: ${ONION_ADDRESS}"

exec su-exec tor tor -f /etc/tor/torrc
ENTRYPOINT


RUN chmod 0755 /usr/local/bin/entrypoint.sh


# ============================================================
# Runtime
# ============================================================

EXPOSE 8080


HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=20s \
    --retries=3 \
    CMD pidof tor >/dev/null \
        && wget -q -O /dev/null http://127.0.0.1:8080/_health \
        || exit 1


CMD ["/usr/local/bin/entrypoint.sh"]
