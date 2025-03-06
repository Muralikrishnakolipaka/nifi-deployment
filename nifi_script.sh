#!/bin/bash

# --- Load environment variables from .env file ---
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found!"
    exit 1
fi

# --- Configuration ---
DOMAIN_NAME="nifi-prod.bluedotspace.io"
EMAIL="muralikrishna.k@inndata.in"
NIFI_BACKEND_ADDRESS="10.0.0.6:9443"

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

keytool -genkeypair -alias nifi-key -keyalg RSA -keystore keystore.jks -storepass "\$KEYSTORE_PASSWORD" -validity 3650 -keysize 2048 -dname "CN=$DOMAIN_NAME, OU=IT, O=MyOrg, L=City, ST=State, C=US"
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

sudo dnf update -y
sudo dnf install -y epel-release
sudo dnf install -y nginx certbot python3-certbot-nginx

cat <<'NGINX_CONF' | sudo tee /etc/nginx/conf.d/$DOMAIN_NAME.conf

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

sudo nginx -t
if [ \$? -ne 0 ]; then
  echo "Nginx configuration test failed. Exiting."
  exit 1
fi

if [ -d /etc/letsencrypt/live/$DOMAIN_NAME ]; then
    echo "SSL certificate already exists for $DOMAIN_NAME. Skipping Certbot."
else
    echo "Obtaining SSL certificate for $DOMAIN_NAME..."
    sudo certbot --nginx -d "$DOMAIN_NAME" --non-interactive --agree-tos --email "$EMAIL"
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

echo "Creating Dockerfile in $NIFI_DIR..."
cd "$NIFI_DIR"

cat <<EOF > Dockerfile
FROM apache/nifi:2.2.0
USER root
LABEL org.label-schema.vendor="Bluedotspace"
LABEL org.label-schema.name="Apache NiFi with OIDC"
LABEL org.label-schema.version="1.0"
COPY authorizers.xml /opt/nifi/nifi-current/conf/
COPY nifi.properties /opt/nifi/nifi-current/conf/
RUN chown -R nifi:nifi /opt/nifi/nifi-current/conf/
RUN mkdir -p /opt/certs/
RUN ln -snf /usr/share/zoneinfo/Asia/Kolkata /etc/localtime && echo Asia/Kolkata > /etc/timezone
HEALTHCHECK --interval=5m --timeout=3s --retries=3 CMD curl -k https://localhost:9443/nifi/ || exit 1
EOF
cd "$SCRIPT_DIR"

# --- Confirmation ---
echo "All files and configurations have been created successfully."

# --- NiFi Configuration Files ---
echo "Creating required NiFi configuration files..."

# Generate nifi.properties
if [ ! -f "$NIFI_DIR/nifi.properties" ]; then
    echo "Creating nifi.properties..."
    cat <<'EOF' > "$NIFI_DIR/nifi.properties"
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Core Properties #
nifi.flow.configuration.file=./conf/flow.json.gz
nifi.flow.configuration.archive.enabled=true
nifi.flow.configuration.archive.dir=./conf/archive/
nifi.flow.configuration.archive.max.time=30 days
nifi.flow.configuration.archive.max.storage=500 MB
nifi.flow.configuration.archive.max.count=
nifi.flowcontroller.autoResumeState=true
nifi.flowcontroller.graceful.shutdown.period=10 sec
nifi.flowservice.writedelay.interval=500 ms
nifi.administrative.yield.duration=30 sec
# If a component has no work to do (is "bored"), how long should we wait before checking again for work?
nifi.bored.yield.duration=10 millis
nifi.queue.backpressure.count=10000
nifi.queue.backpressure.size=1 GB

nifi.authorizer.configuration.file=./conf/authorizers.xml
nifi.login.identity.provider.configuration.file=./conf/login-identity-providers.xml
nifi.ui.banner.text=
nifi.nar.library.directory=./lib
nifi.nar.library.autoload.directory=/opt/nifi/nifi-current/nar_extensions
nifi.nar.working.directory=./work/nar/
nifi.nar.unpack.uber.jar=false
nifi.upload.working.directory=./work/uploads

#####################
# Python Extensions #
#####################
# Uncomment in order to enable Python Extensions.
nifi.python.command=python3
nifi.python.framework.source.directory=./python/framework
nifi.python.extensions.source.directory.default=/opt/nifi/nifi-current/python_extensions
nifi.python.working.directory=./work/python
nifi.python.max.processes=100
nifi.python.max.processes.per.extension.type=10

####################
# State Management #
####################
nifi.state.management.configuration.file=./conf/state-management.xml
# The ID of the local state provider
nifi.state.management.provider.local=local-provider
# The ID of the cluster-wide state provider. This will be ignored if NiFi is not clustered but must be populated if running in a cluster.
nifi.state.management.provider.cluster=zk-provider
# The Previous Cluster State Provider from which the framework will load Cluster State when the current Cluster Provider has no entries
nifi.state.management.provider.cluster.previous=
# Specifies whether or not this instance of NiFi should run an embedded ZooKeeper server
nifi.state.management.embedded.zookeeper.start=false
# Properties file that provides the ZooKeeper properties to use if <nifi.state.management.embedded.zookeeper.start> is set to true
nifi.state.management.embedded.zookeeper.properties=./conf/zookeeper.properties

# Database Settings
nifi.database.directory=./database_repository

# FlowFile Repository
nifi.flowfile.repository.implementation=org.apache.nifi.controller.repository.WriteAheadFlowFileRepository
nifi.flowfile.repository.wal.implementation=org.apache.nifi.wali.SequentialAccessWriteAheadLog
nifi.flowfile.repository.directory=./flowfile_repository
nifi.flowfile.repository.checkpoint.interval=20 secs
nifi.flowfile.repository.always.sync=false
nifi.flowfile.repository.retain.orphaned.flowfiles=true

nifi.swap.manager.implementation=org.apache.nifi.controller.FileSystemSwapManager
nifi.queue.swap.threshold=20000

# Content Repository
nifi.content.repository.implementation=org.apache.nifi.controller.repository.FileSystemRepository
nifi.content.claim.max.appendable.size=50 KB
nifi.content.repository.directory.default=./content_repository
nifi.content.repository.archive.max.retention.period=3 hours
nifi.content.repository.archive.max.usage.percentage=90%
nifi.content.repository.archive.enabled=true
nifi.content.repository.always.sync=false

# Provenance Repository Properties
nifi.provenance.repository.implementation=org.apache.nifi.provenance.WriteAheadProvenanceRepository

# Persistent Provenance Repository Properties
nifi.provenance.repository.directory.default=./provenance_repository
nifi.provenance.repository.max.storage.time=30 days
nifi.provenance.repository.max.storage.size=10 GB
nifi.provenance.repository.rollover.time=10 mins
nifi.provenance.repository.rollover.size=100 MB
nifi.provenance.repository.query.threads=2
nifi.provenance.repository.index.threads=2
nifi.provenance.repository.compress.on.rollover=true
nifi.provenance.repository.always.sync=false
# Comma-separated list of fields. Fields that are not indexed will not be searchable. Valid fields are:
# EventType, FlowFileUUID, Filename, TransitURI, ProcessorID, AlternateIdentifierURI, Relationship, Details
nifi.provenance.repository.indexed.fields=EventType, FlowFileUUID, Filename, ProcessorID, Relationship
# FlowFile Attributes that should be indexed and made searchable.  Some examples to consider are filename, uuid, mime.type
nifi.provenance.repository.indexed.attributes=
# Large values for the shard size will result in more Java heap usage when searching the Provenance Repository
# but should provide better performance
nifi.provenance.repository.index.shard.size=500 MB
# Indicates the maximum length that a FlowFile attribute can be when retrieving a Provenance Event from
# the repository. If the length of any attribute exceeds this value, it will be truncated when the event is retrieved.
nifi.provenance.repository.max.attribute.length=65536
nifi.provenance.repository.concurrent.merge.threads=2


# Volatile Provenance Respository Properties
nifi.provenance.repository.buffer.size=100000

# Component and Node Status History Repository
nifi.components.status.repository.implementation=org.apache.nifi.controller.status.history.VolatileComponentStatusRepository

# Volatile Status History Repository Properties
nifi.components.status.repository.buffer.size=1440
nifi.components.status.snapshot.frequency=1 min

# QuestDB Status History Repository Properties
nifi.status.repository.questdb.persist.node.days=14
nifi.status.repository.questdb.persist.component.days=3
nifi.status.repository.questdb.persist.location=./status_repository

# NAR Persistence Properties
nifi.nar.persistence.provider.implementation=org.apache.nifi.nar.StandardNarPersistenceProvider
nifi.nar.persistence.provider.properties.directory=./nar_repository

# Asset Management
nifi.asset.manager.implementation=org.apache.nifi.asset.StandardAssetManager
nifi.asset.manager.properties.directory=./assets

# Site to Site properties
nifi.remote.input.host=$DOMAIN_NAME
nifi.remote.input.secure=true
nifi.remote.input.socket.port=10000
nifi.remote.input.http.enabled=true
nifi.remote.input.http.transaction.ttl=30 sec
nifi.remote.contents.cache.expiration=30 secs

# web properties #
#############################################

# For security, NiFi will present the UI on 127.0.0.1 and only be accessible through this loopback interface.
# Be aware that changing these properties may affect how your instance can be accessed without any restriction.
# We recommend configuring HTTPS instead. The administrators guide provides instructions on how to do this.

nifi.web.http.host=
nifi.web.http.port=
nifi.web.http.network.interface.default=

#############################################

nifi.web.https.host=$DOMAIN_NAME
nifi.web.https.port=9443
nifi.web.https.network.interface.default=
nifi.web.https.application.protocols=h2 http/1.1
nifi.web.jetty.working.directory=./work/jetty
nifi.web.jetty.threads=200
nifi.web.max.header.size=16 KB
nifi.web.proxy.context.path=
nifi.web.proxy.host=$DOMAIN_NAME:443,$DOMAIN_NAME,nifi:9443,10.0.0.6:9443
nifi.web.max.content.size=
nifi.web.max.requests.per.second=30000
nifi.web.max.access.token.requests.per.second=25
nifi.web.request.timeout=60 secs
nifi.web.request.ip.whitelist=
nifi.web.should.send.server.version=true
nifi.web.request.log.format=%{client}a - %u %t "%r" %s %O "%{Referer}i" "%{User-Agent}i"

# Filter JMX MBeans available through the System Diagnostics REST API
nifi.web.jmx.metrics.allowed.filter.pattern=

# Include or Exclude TLS Cipher Suites for HTTPS
nifi.web.https.ciphersuites.include=
nifi.web.https.ciphersuites.exclude=

# security properties #
nifi.sensitive.props.key=BulLIddwRNkEcrLQdAD+loK+Odim4HK+HlCyJZny9qU=
nifi.sensitive.props.algorithm=NIFI_PBKDF2_AES_GCM_256

nifi.security.autoreload.enabled=false
nifi.security.autoreload.interval=10 secs
nifi.security.keystore=/opt/nifi/nifi-current/conf/keystore.jks
nifi.security.keystore.certificate=
nifi.security.keystore.privateKey=
nifi.security.keystoreType=JKS
nifi.security.keystorePasswd=MyKeystorePass
nifi.security.keyPasswd=MyKeystorePass
nifi.security.truststore=/opt/nifi/nifi-current/conf/truststore.jks
nifi.security.truststore.certificate=
nifi.security.truststoreType=JKS
nifi.security.truststorePasswd=MyTruststorePass

nifi.security.user.authorizer=managed-authorizer
nifi.security.allow.anonymous.authentication=false
nifi.security.user.login.identity.provider=
nifi.security.user.jws.key.rotation.period=PT1H
nifi.security.ocsp.responder.url=
nifi.security.ocsp.responder.certificate=

# OpenId Connect SSO Properties #
nifi.security.user.oidc.discovery.url=https://login.microsoftonline.com/b309ea5a-b8e2-49d5-bbb7-232c6d9008d7/v2.0/.well-known/openid-configuration
nifi.security.user.oidc.connect.timeout=5 secs
nifi.security.user.oidc.read.timeout=5 secs
nifi.security.user.oidc.client.id=86bd7eab-1a05-4b89-b953-228771ef86dc
nifi.security.user.oidc.client.secret=REMOVED_SECRET
nifi.security.user.oidc.preferred.jwsalgorithm=
nifi.security.user.oidc.additional.scopes=openid,email,profile
nifi.security.user.oidc.claim.identifying.user=email
nifi.security.user.oidc.fallback.claims.identifying.user=upn
nifi.security.user.oidc.claim.groups=groups
nifi.security.user.oidc.truststore.strategy=JDK
nifi.security.user.oidc.token.refresh.window=60 secs

# SAML Properties #
nifi.security.user.saml.idp.metadata.url=
nifi.security.user.saml.sp.entity.id=
nifi.security.user.saml.identity.attribute.name=
nifi.security.user.saml.group.attribute.name=
nifi.security.user.saml.request.signing.enabled=false
nifi.security.user.saml.want.assertions.signed=true
nifi.security.user.saml.signature.algorithm=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
nifi.security.user.saml.authentication.expiration=12 hours
nifi.security.user.saml.single.logout.enabled=false
nifi.security.user.saml.http.client.truststore.strategy=JDK
nifi.security.user.saml.http.client.connect.timeout=30 secs
nifi.security.user.saml.http.client.read.timeout=30 secs

# Identity Mapping Properties #
# These properties allow normalizing user identities such that identities coming from different identity providers
# (certificates, LDAP, Kerberos) can be treated the same internally in NiFi. The following example demonstrates normalizing
# DNs from certificates and principals from Kerberos into a common identity string:
#
# nifi.security.identity.mapping.pattern.dn=^CN=(.*?), OU=(.*?), O=(.*?), L=(.*?), ST=(.*?), C=(.*?)$
# nifi.security.identity.mapping.value.dn=$1@$2
# nifi.security.identity.mapping.transform.dn=NONE
# nifi.security.identity.mapping.pattern.kerb=^(.*?)/instance@(.*?)$
# nifi.security.identity.mapping.value.kerb=$1@$2
# nifi.security.identity.mapping.transform.kerb=UPPER

# Group Mapping Properties #
# These properties allow normalizing group names coming from external sources like LDAP. The following example
# lowercases any group name.
#
# nifi.security.group.mapping.pattern.anygroup=^(.*)$
# nifi.security.group.mapping.value.anygroup=$1
# nifi.security.group.mapping.transform.anygroup=LOWER

# cluster common properties (all nodes must have same values) #
nifi.cluster.protocol.heartbeat.interval=5 sec
nifi.cluster.protocol.heartbeat.missable.max=8
nifi.cluster.protocol.is.secure=false

# cluster node properties (only configure for cluster nodes) #
nifi.cluster.is.node=false
nifi.cluster.leader.election.implementation=CuratorLeaderElectionManager
nifi.cluster.node.address=$DOMAIN_NAME
nifi.cluster.node.protocol.port=
nifi.cluster.node.protocol.max.threads=50
nifi.cluster.node.event.history.size=25
nifi.cluster.node.connection.timeout=5 sec
nifi.cluster.node.read.timeout=5 sec
nifi.cluster.node.max.concurrent.requests=100
nifi.cluster.firewall.file=
nifi.cluster.flow.election.max.wait.time=5 mins
nifi.cluster.flow.election.max.candidates=

# cluster load balancing properties #
nifi.cluster.load.balance.host=
nifi.cluster.load.balance.port=6342
nifi.cluster.load.balance.connections.per.node=1
nifi.cluster.load.balance.max.thread.count=8
nifi.cluster.load.balance.comms.timeout=30 sec

# zookeeper properties, used for cluster management #
nifi.zookeeper.connect.string=
nifi.zookeeper.connect.timeout=10 secs
nifi.zookeeper.session.timeout=10 secs
nifi.zookeeper.root.node=/nifi
nifi.zookeeper.client.secure=false
nifi.zookeeper.security.keystore=
nifi.zookeeper.security.keystoreType=
nifi.security.keystorePasswd=
nifi.security.truststore=
nifi.security.truststoreType=
nifi.security.truststorePasswd=
nifi.zookeeper.jute.maxbuffer=

# Zookeeper properties for the authentication scheme used when creating acls on znodes used for cluster management
# Values supported for nifi.zookeeper.auth.type are "default", which will apply world/anyone rights on znodes
# and "sasl" which will give rights to the sasl/kerberos identity used to authenticate the nifi node
# The identity is determined using the value in nifi.kerberos.service.principal and the removeHostFromPrincipal
# and removeRealmFromPrincipal values (which should align with the kerberos.removeHostFromPrincipal and kerberos.removeRealmFromPrincipal
# values configured on the zookeeper server).
nifi.zookeeper.auth.type=
nifi.zookeeper.kerberos.removeHostFromPrincipal=
nifi.zookeeper.kerberos.removeRealmFromPrincipal=

# kerberos #
nifi.kerberos.krb5.file=

# kerberos service principal #
nifi.kerberos.service.principal=
nifi.kerberos.service.keytab.location=

# analytics properties #
nifi.analytics.predict.enabled=false
nifi.analytics.predict.interval=3 mins
nifi.analytics.query.interval=5 mins
nifi.analytics.connection.model.implementation=org.apache.nifi.controller.status.analytics.models.OrdinaryLeastSquares
nifi.analytics.connection.model.score.name=rSquared
nifi.analytics.connection.model.score.threshold=.90

# kubernetes #
nifi.cluster.leader.election.kubernetes.lease.prefix=

# flow analysis properties
nifi.registry.check.for.rule.violations.before.commit=

# runtime monitoring properties
nifi.monitor.long.running.task.schedule=
nifi.monitor.long.running.task.threshold=

# Enable automatic diagnostic at shutdown.
nifi.diagnostics.on.shutdown.enabled=false

# Include verbose diagnostic information.
nifi.diagnostics.on.shutdown.verbose=false

# The location of the diagnostics folder.
nifi.diagnostics.on.shutdown.directory=./diagnostics

# The maximum number of files permitted in the directory. If the limit is exceeded, the oldest files are deleted.
nifi.diagnostics.on.shutdown.max.filecount=10

# The diagnostics folder's maximum permitted size in bytes. If the limit is exceeded, the oldest files are deleted.
nifi.diagnostics.on.shutdown.max.directory.size=10 MB

# Performance tracking properties
## Specifies what percentage of the time we should track the amount of time processors are using CPU, reading from/writing to content repo, etc.## This can be useful to understand which components are the most expensive and to understand where system bottlenecks may be occurring.
## The value must be in the range of 0 (inclusive) to 100 (inclusive). A larger value will produce more accurate results, while a smaller value may be
## less expensive to compute.
## Results can be obtained by running "nifi.sh diagnostics <filename>" and then inspecting the produced file.
nifi.performance.tracking.percentage=0

# NAR Provider Properties #
# These properties allow configuring one or more NAR providers. A NAR provider retrieves NARs from an external source
# and copies them to the directory specified by nifi.nar.library.autoload.directory.
#
# Each NAR provider property follows the format:
#  nifi.nar.library.provider.<identifier>.<property-name>
#
# Each NAR provider must have at least one property named "implementation".
#
# Example HDFS NAR Provider:
#   nifi.nar.library.provider.hdfs.implementation=org.apache.nifi.flow.resource.hadoop.HDFSExternalResourceProvider
#   nifi.nar.library.provider.hdfs.resources=/path/to/core-site.xml,/path/to/hdfs-site.xml
#   nifi.nar.library.provider.hdfs.storage.location=hdfs://hdfs-location
#   nifi.nar.library.provider.hdfs.source.directory=/nars
#   nifi.nar.library.provider.hdfs.kerberos.principal=nifi@NIFI.COM
#   nifi.nar.library.provider.hdfs.kerberos.keytab=/path/to/nifi.keytab
#   nifi.nar.library.provider.hdfs.kerberos.password=
#
# Example NiFi Registry NAR Provider:
#   nifi.nar.library.provider.nifi-registry.implementation=org.apache.nifi.registry.extension.NiFiRegistryExternalResourceProvider
#   nifi.nar.library.provider.nifi-registry.url=http://localhost:18080

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
        <property name="Client Secret">{AZURE_CLIENT_SECRET}</property>
        <property name="Group Filter Prefix">Nifi</property>
        <property name="Group Filter Suffix"></property>
        <property name="Group Filter Substring"></property>
        <property name="Group Filter List Inclusion">NiFi-Admins,NiFi-Users</property>
        <property name="Page Size">100</property>
        <property name="Claim for Username">email</property>
    </userGroupProvider>
    <userGroupProvider>
        <identifier>composite-configurable-user-group-provider</identifier>
        <class>org.apache.nifi.authorization.CompositeConfigurableUserGroupProvider</class>
        <property name="Configurable User Group Provider">file-user-group-provider</property>
        <property name="User Group Provider 1">azure-graph-user-group-provider</property>
    </userGroupProvider>
    <accessPolicyProvider>
        <identifier>file-access-policy-provider</identifier>
        <class>org.apache.nifi.authorization.FileAccessPolicyProvider</class>
        <property name="User Group Provider">composite-configurable-user-group-provider</property>
        <property name="Authorizations File">./conf/authorizations.xml</property>
        <property name="Initial Admin Identity">muralikrishna.k@inndata.in</property>
        <property name="Legacy Authorized Users File"></property>
        <property name="Node Identity 1"></property>
        <property name="Node Group"></property>
    </accessPolicyProvider>
    <authorizer>
        <identifier>managed-authorizer</identifier>
        <class>org.apache.nifi.authorization.StandardManagedAuthorizer</class>
        <property name="Access Policy Provider">file-access-policy-provider</property>
    </authorizer>
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
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
      - NIFI_SECURITY_USER_AUTHORIZER=managed-authorizer
      - NIFI_WEB_PROXY_HOST=$DOMAIN_NAME:9443
    volumes:
      - ./cert/$DOMAIN_NAME/keystore.jks:/opt/certs/keystore.jks
      - ./cert/$DOMAIN_NAME/truststore.jks:/opt/certs/truststore.jks
    ports:
      - "9443:9443"
networks:
  internal:
    driver: bridge
EOF

# --- Build and Start ---
echo "Building and starting the environment..."
docker compose build
docker compose up -d

echo "Automation complete! NiFi is available at https://$DOMAIN_NAME:9443"
