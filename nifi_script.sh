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
CERT_DIR="$BASE_DIR/cert/$DOMAIN_NAME"
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

sudo dnf update -y
sudo dnf install -y epel-release
sudo dnf install -y nginx certbot python3-certbot-nginx

cat <<'NGINX_CONF' | sudo tee /etc/nginx/conf.d/\$DOMAIN_NAME.conf

server {
    server_name nifi-prod.bluedotspace.io;
    location / {
        proxy_pass https://$NIFI_BACKEND_ADDRESS;
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

sudo nginx -t
if [ \$? -ne 0 ]; then
  echo "Nginx configuration test failed. Exiting."
  exit 1
fi

if [ -d /etc/letsencrypt/live/\$DOMAIN_NAME ]; then
    echo "SSL certificate already exists for \$DOMAIN_NAME. Skipping Certbot."
else
    echo "Obtaining SSL certificate for \$DOMAIN_NAME..."
    sudo certbot --nginx -d "\$DOMAIN_NAME" --non-interactive --agree-tos --email "\$EMAIL"
fi

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

# --- NiFi Configuration Files ---
echo "Creating required NiFi configuration files..."

# Generate nifi.properties
if [ ! -f "$NIFI_DIR/nifi.properties" ]; then
    echo "Creating nifi.properties..."
    cat <<EOF > "$NIFI_DIR/nifi.properties"
nifi.web.https.host=$DOMAIN_NAME
nifi.web.https.port=8443
nifi.security.keystore=/opt/nifi/nifi-current/conf/keystore.jks
nifi.security.keystoreType=JKS
nifi.security.keystorePasswd=$KEYSTORE_PASSWORD
nifi.security.truststore=/opt/nifi/nifi-current/conf/truststore.jks
nifi.security.truststoreType=JKS
nifi.security.truststorePasswd=$TRUSTSTORE_PASSWORD
nifi.security.user.authorizer=managed-authorizer
EOF
else
    echo "nifi.properties already exists. Skipping creation."
fi

# Generate authorizers.xml
if [ ! -f "$NIFI_DIR/authorizers.xml" ]; then
    echo "Creating authorizers.xml..."
    cat <<EOF > "$NIFI_DIR/authorizers.xml"
<?xml version="1.0" encoding="UTF-8"?>
<authorizers>
    <userGroupProvider>
        <identifier>file-user-group-provider</identifier>
        <class>org.apache.nifi.authorization.FileUserGroupProvider</class>
        <property name="Users File">./conf/users.xml</property>
        <property name="Legacy Authorized Users File"></property>
    </userGroupProvider>
    <userGroupProvider>
        <identifier>azure-graph-user-group-provider</identifier>
        <class>org.apache.nifi.authorization.azure.AzureGraphUserGroupProvider</class>
        <property name="Refresh Delay">5 mins</property>
        <property name="Authority Endpoint">https://login.microsoftonline.com</property>
        <property name="Directory ID">b309ea5a-b8e2-49d5-bbb7-232c6d9008d7</property>
        <property name="Application ID">86bd7eab-1a05-4b89-b953-228771ef86dc</property>
        <property name="Client Secret">REMOVED_SECRET</property>
        <property name="Claim for Username">email</property>
    </userGroupProvider>
    <accessPolicyProvider>
        <identifier>file-access-policy-provider</identifier>
        <class>org.apache.nifi.authorization.FileAccessPolicyProvider</class>
        <property name="User Group Provider">file-user-group-provider</property>
        <property name="Authorizations File">./conf/authorizations.xml</property>
    </accessPolicyProvider>
</authorizers>
EOF
else
    echo "authorizers.xml already exists. Skipping creation."
fi

# --- Docker Compose ---
echo "Creating docker-compose.yml..."
cat <<EOF > docker-compose.yml
version: '3.8'
services:
  nifi:
    build:
      context: ./nifi
    container_name: nifi
    hostname: $DOMAIN_NAME
    networks:
      - internal
    environment:
      - NIFI_WEB_HTTPS_PORT=8443
    volumes:
      - ./cert/$DOMAIN_NAME/keystore.jks:/opt/certs/keystore.jks
      - ./cert/$DOMAIN_NAME/truststore.jks:/opt/certs/truststore.jks
    ports:
      - "8443:8443"
networks:
  internal:
    driver: bridge
EOF

# --- Build and Start ---
echo "Building and starting the environment..."
sudo docker compose build
sudo docker compose up -d

echo "Automation complete! NiFi is available at https://$DOMAIN_NAME:8443"

