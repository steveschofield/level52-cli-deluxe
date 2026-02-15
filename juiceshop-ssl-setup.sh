#!/usr/bin/env bash
set -euo pipefail

# ========= CONFIG (edit if you want) =========
DOMAIN="juiceshop.ss.hackme"
PROJECT_DIR="${PWD}/juiceshop-ssl"
NGINX_DIR="${PROJECT_DIR}/nginx"
CERT_DIR="${PROJECT_DIR}/certs"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
NGINX_CONF="${NGINX_DIR}/default.conf"

# ========= HELPERS =========
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }

cleanup_old() {
  # Remove any old containers with these names (your conflict issue)
  for name in juiceshop-nginx juiceshop; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
      echo "[*] Removing old container: $name"
      docker rm -f "$name" >/dev/null
    fi
  done
}

ensure_hosts() {
  if grep -qE "^[[:space:]]*127\.0\.0\.1[[:space:]]+${DOMAIN}([[:space:]]+|$)" /etc/hosts; then
    echo "[*] /etc/hosts already has ${DOMAIN}"
  else
    echo "[*] Adding ${DOMAIN} to /etc/hosts (sudo required)"
    echo "127.0.0.1 ${DOMAIN}" | sudo tee -a /etc/hosts >/dev/null
  fi
}

make_dirs() {
  mkdir -p "$NGINX_DIR" "$CERT_DIR"

  # Fix your exact problem: if default.conf path is a directory, remove it.
  if [ -d "$NGINX_CONF" ]; then
    echo "[*] Found directory at ${NGINX_CONF} (should be a file). Removing it."
    rm -rf "$NGINX_CONF"
  fi
}

gen_cert() {
  local crt="${CERT_DIR}/juiceshop.crt"
  local key="${CERT_DIR}/juiceshop.key"

  if [[ -f "$crt" && -f "$key" ]]; then
    echo "[*] Cert already exists: ${crt}"
    return
  fi

  echo "[*] Generating self-signed cert for ${DOMAIN}"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$key" -out "$crt" -days 365 \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1"
}

write_nginx_conf() {
  echo "[*] Writing nginx default.conf"
  cat > "$NGINX_CONF" <<EOF
server {
  listen 443 ssl;
  server_name ${DOMAIN};

  ssl_certificate     /etc/nginx/certs/juiceshop.crt;
  ssl_certificate_key /etc/nginx/certs/juiceshop.key;

  location / {
    proxy_pass http://juiceshop:3000;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }
}

server {
  listen 80;
  server_name ${DOMAIN};
  return 301 https://\$host\$request_uri;
}
EOF
}

write_compose() {
  echo "[*] Writing docker-compose.yml"
  cat > "$COMPOSE_FILE" <<'EOF'
services:
  juiceshop:
    image: bkimminich/juice-shop:latest
    container_name: juiceshop
    restart: unless-stopped
    expose:
      - "3000"

  nginx:
    image: nginx:alpine
    container_name: juiceshop-nginx
    restart: unless-stopped
    depends_on:
      - juiceshop
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/nginx/certs:ro
EOF
}

start_stack() {
  echo "[*] Starting stack"
  (cd "$PROJECT_DIR" && docker compose up -d)

  echo
  echo "[+] Done."
  echo "    HTTPS: https://${DOMAIN}"
  echo "    (accept the browser cert warning — it's self-signed)"
}

# ========= MAIN =========
need docker
need openssl

echo "[*] Project dir: $PROJECT_DIR"
make_dirs
gen_cert
write_nginx_conf
write_compose

# Uncomment if you want the script to always manage /etc/hosts:
ensure_hosts

cleanup_old
start_stack
