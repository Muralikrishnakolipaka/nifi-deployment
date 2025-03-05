#!/bin/bash

# --- Configuration ---
DOMAIN_NAME="nifi-prod.bluedotspace.io"  # Your domain name
EMAIL="muralikrishna.k@inndata.in"       # Your email for Let's Encrypt
KEYSTORE_PASSWORD="MyKeystorePass"       # A strong password for keystore
TRUSTSTORE_PASSWORD="MyTruststorePass"   # A strong password for truststore
NIFI_BACKEND_ADDRESS="10.0.0.6:9443"     # NiFi backend address (IP:port or container name:port)

# --- Directory Structure ---
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
BASE_DIR="$SCRIPT_DIR"
CERT_DIR="$BASE_DIR/cert/nifi-prod.bluedotspace.io"
NGINX_DIR="$BASE_DIR/nginx"
NIFI_DIR="$BASE_DIR/nifi"

# --- Stop on error ---
set -e

# --- Create directories ---
echo "Checking if directories exist..."
mkdir -p "$CERT_DIR"
mkdir -p "$NGINX_DIR"
mkdir -p "$NIFI_DIR"

# --- Generate Certificates ---
echo "Checking if keystore exists..."
cd "$CERT_DIR"
if [ -f keystore.jks ]; then
    echo "Keystore already exists. Skipping certificate generation."
else
    echo "Generating Certificates..."
    cat <<EOF > generate_certs.sh
#!/bin/bash
set -e
DOMAIN_NAME="$DOMAIN_NAME"
KEYSTORE_PASSWORD="$KEYSTORE_PASSWORD"
TRUSTSTORE_PASSWORD="$TRUSTSTORE_PASSWORD"

keytool -genkeypair -alias nifi-key -keyalg RSA -keystore keystore.jks -storepass "\$KEYSTORE_PASSWORD" -validity 3650 -keysize 2048 -dname "CN=\$DOMAIN_NAME, OU=IT, O=MyOrg, L=City, ST=State, C=US"
keytool -exportcert -alias nifi-key -keystore keystore.jks -file nifi-cert.pem -storepass "\$KEYSTORE_PASSWORD"
keytool -importcert -alias nifi-trust -keystore truststore.jks -file nifi-cert.pem -storepass "\$TRUSTSTORE_PASSWORD" -noprompt
EOF

    chmod +x generate_certs.sh
    ./generate_certs.sh
fi
cd "$SCRIPT_DIR"

# --- Nginx Configuration ---
echo "Configuring Nginx..."
cd "$NGINX_DIR"

cat <<EOF > install_nginx.sh
#!/bin/bash
set -e
DOMAIN_NAME="$DOMAIN_NAME"
EMAIL="$EMAIL"
NIFI_BACKEND_ADDRESS="$NIFI_BACKEND_ADDRESS"

# Install Nginx and Certbot
sudo dnf update -y
sudo dnf install -y epel-release
sudo dnf install -y nginx certbot python3-certbot-nginx

cat <<'NGINX_CONF' | sudo tee /etc/nginx/conf.d/\$DOMAIN_NAME.conf

server {
    server_name nifi-prod.bluedotspace.io;
    location / {
        proxy_pass https://10.0.0.6:9443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }
}

NGINX_CONF

# Test Nginx Configuration
sudo nginx -t
if [ \$? -ne 0 ]; then
  echo "Nginx configuration test failed. Exiting."
  exit 1
fi

# Obtain SSL Certificates if not already present
if [ -d /etc/letsencrypt/live/\$DOMAIN_NAME ]; then
    echo "SSL certificate already exists for \$DOMAIN_NAME. Skipping Certbot."
else
    echo "Obtaining SSL certificate for \$DOMAIN_NAME..."
    sudo certbot --nginx -d "\$DOMAIN_NAME" --non-interactive --agree-tos --email "\$EMAIL"
fi

# Check if Nginx is active, restart if not
if ! sudo systemctl is-active --quiet nginx; then
    echo "Nginx is not active. Starting Nginx..."
    sudo systemctl start nginx
else
    echo "Nginx is active. Reloading configuration..."
    sudo systemctl reload nginx
fi
EOF

chmod +x install_nginx.sh
sudo ./install_nginx.sh
cd "$SCRIPT_DIR"

# --- NiFi Configuration ---
echo "Configuring NiFi..."
cd "$NIFI_DIR"

cat <<EOF > Dockerfile
FROM apache/nifi:2.2.0
USER root
LABEL org.label-schema.vendor="YourOrg"
LABEL org.label-schema.name="Apache NiFi with OIDC"
LABEL org.label-schema.version="1.0"
COPY authorizers.xml /opt/nifi/nifi-current/conf/
COPY nifi.properties /opt/nifi/nifi-current/conf/
RUN chown -R nifi:nifi /opt/nifi/nifi-current/conf/
RUN mkdir -p /opt/certs/
RUN ln -snf /usr/share/zoneinfo/Asia/Kolkata /etc/localtime && echo Asia/Kolkata > /etc/timezone
HEALTHCHECK --interval=5m --timeout=3s --retries=3 CMD curl -f https://localhost:9443/nifi || exit 1
EOF

# NiFi Properties and Authorizers XML setup
cd ../..

# --- Docker Compose ---
echo "Checking permissions for docker-compose.yml..."
if [ ! -w "$SCRIPT_DIR" ]; then
    echo "Directory $SCRIPT_DIR is not writable. Updating permissions..."
    sudo chmod -R u+w "$SCRIPT_DIR"
fi

echo "Creating docker-compose.yml..."
sudo tee docker-compose.yml > /dev/null <<EOF
version: '3.8'
services:
  nifi:
    build:
      context: /var/lib/jenkins/nifi
    container_name: nifi
    hostname: \$DOMAIN_NAME
    networks:
      - internal
    environment:
      - TZ=Asia/Kolkata
      - NIFI_WEB_HTTPS_PORT=9443
      - NIFI_CLUSTER_IS_NODE=false
      - NIFI_CLUSTER_PROTOCOL_IS_SECURE=true
      - NIFI_WEB_PROXY_HOST=\$DOMAIN_NAME:9443
      - NIFI_SECURITY_USER_AUTHORIZER=managed-authorizer
      - AUTH=tls
      - KEYSTORE_PATH=/opt/certs/keystore.jks
      - KEYSTORE_TYPE=JKS
      - KEYSTORE_PASSWORD=\$KEYSTORE_PASSWORD
      - TRUSTSTORE_PATH=/opt/certs/truststore.jks
      - TRUSTSTORE_TYPE=JKS
      - TRUSTSTORE_PASSWORD=\$TRUSTSTORE_PASSWORD
      - NIFI_SECURITY_USER_OIDC_ENABLED=true
      - NIFI_SECURITY_USER_OIDC_DISCOVERY_URL=https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration
      - NIFI_SECURITY_USER_OIDC_CLIENT_ID=<CLIENT_ID>
      - NIFI_SECURITY_USER_OIDC_CLIENT_SECRET=<CLIENT_SECRET>
      - NIFI_SECURITY_USER_OIDC_CLAIM_IDENTIFYING_USER=email
    volumes:
      - ./cert/nifi-prod.bluedotspace.io/keystore.jks:/opt/certs/keystore.jks
      - ./cert/nifi-prod.bluedotspace.io/truststore.jks:/opt/certs/truststore.jks
    ports:
      - "9443:9443"
    restart: always

networks:
  internal:
    driver: bridge
EOF

# --- Build and Start ---
echo "Building and starting the environment..."
sudo docker compose build
sudo docker compose up -d

echo "Automation complete!"
echo "NiFi: https://$DOMAIN_NAME:9443"

