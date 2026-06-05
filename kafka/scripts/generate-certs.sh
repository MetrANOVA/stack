#!/usr/bin/env bash
set -euo pipefail

SECRETS_DIR="/etc/kafka/secrets"
KEYSTORE_PATH="$SECRETS_DIR/kafka.keystore.jks"
TRUSTSTORE_PATH="$SECRETS_DIR/kafka.truststore.jks"
CLIENT_PROPS_PATH="${KAFKA_CLIENT_PROPERTIES_PATH:-/config/client.properties}"
CA_CERT_PATH="$SECRETS_DIR/ca.crt"
CONFIG_CA_PATH="/config/ca.crt"
CONFIG_EXPORT_DIR="/config/export"
CONFIG_EXPORT_CA_PATH="$CONFIG_EXPORT_DIR/ca.crt"
CLUSTER_ID_PATH="$SECRETS_DIR/cluster_id"

KSTORE_PASS="${KAFKA_SSL_KEYSTORE_PASSWORD:-changeit}"
TSTORE_PASS="${KAFKA_SSL_TRUSTSTORE_PASSWORD:-changeit}"
KEY_PASS="${KAFKA_SSL_KEY_PASSWORD:-changeit}"
DNS_NAME="${KAFKA_SSL_DNS_NAME:-kafka}"
KEY_ALG="${KAFKA_SSL_KEY_ALG:-RSA}"
KEY_SIZE="${KAFKA_SSL_KEY_SIZE:-2048}"
KAFKA_UID="${KAFKA_UID:-1000}"
KAFKA_GID="${KAFKA_GID:-1000}"

if [[ ! -f "$KEYSTORE_PATH" || ! -f "$TRUSTSTORE_PATH" ]]; then
  WORKDIR="/tmp/kafka-certs"
  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"

  # Generate CA keypair in a temporary keystore using only keytool,
  # avoiding all openssl/Java PKCS12 interop issues.
  keytool -genkeypair \
    -alias CARoot \
    -keyalg "$KEY_ALG" \
    -keysize "$KEY_SIZE" \
    -keystore "$WORKDIR/ca.jks" \
    -storepass "$TSTORE_PASS" \
    -keypass "$TSTORE_PASS" \
    -dname "CN=Kafka-Local-CA" \
    -ext "BasicConstraints:critical=ca:true,pathlen:0" \
    -validity 3650

  # Export CA cert in PEM format for clients
  keytool -exportcert \
    -alias CARoot \
    -keystore "$WORKDIR/ca.jks" \
    -storepass "$TSTORE_PASS" \
    -rfc \
    -file "$WORKDIR/ca.crt"

  # Generate broker keypair directly into the final keystore
  keytool -genkeypair \
    -alias kafka \
    -keyalg "$KEY_ALG" \
    -keysize "$KEY_SIZE" \
    -keystore "$KEYSTORE_PATH" \
    -storepass "$KSTORE_PASS" \
    -keypass "$KEY_PASS" \
    -dname "CN=$DNS_NAME, OU=Dev, O=Local, L=Local, ST=Local, C=US" \
    -validity 3650

  # Generate broker CSR
  keytool -certreq \
    -alias kafka \
    -keystore "$KEYSTORE_PATH" \
    -storepass "$KSTORE_PASS" \
    -file "$WORKDIR/kafka.csr"

  # Sign broker CSR with the CA entirely within keytool (no openssl signing)
  keytool -gencert \
    -alias CARoot \
    -keystore "$WORKDIR/ca.jks" \
    -storepass "$TSTORE_PASS" \
    -infile "$WORKDIR/kafka.csr" \
    -outfile "$WORKDIR/kafka.crt" \
    -validity 3650 \
    -ext "BasicConstraints:critical=ca:false" \
    -ext "SAN=DNS:${DNS_NAME},IP:127.0.0.1" \
    -rfc

  # Create truststore with the CA cert
  keytool -importcert \
    -alias CARoot \
    -file "$WORKDIR/ca.crt" \
    -keystore "$TRUSTSTORE_PATH" \
    -storepass "$TSTORE_PASS" \
    -noprompt

  cp "$WORKDIR/ca.crt" "$CA_CERT_PATH"

  # Import CA cert then signed broker cert into the keystore to complete the chain
  keytool -importcert \
    -alias CARoot \
    -file "$WORKDIR/ca.crt" \
    -keystore "$KEYSTORE_PATH" \
    -storepass "$KSTORE_PASS" \
    -noprompt

  keytool -importcert \
    -alias kafka \
    -file "$WORKDIR/kafka.crt" \
    -keystore "$KEYSTORE_PATH" \
    -storepass "$KSTORE_PASS" \
    -noprompt

  echo "TLS materials created in $SECRETS_DIR"
else
  echo "TLS materials already exist. Skipping generation."
fi

if [[ ! -f "$CA_CERT_PATH" && -f "$TRUSTSTORE_PATH" ]]; then
  keytool -exportcert \
    -alias CARoot \
    -keystore "$TRUSTSTORE_PATH" \
    -storepass "$TSTORE_PASS" \
    -rfc \
    -file "$CA_CERT_PATH" 2>/dev/null || true
fi

if [[ -f "$CA_CERT_PATH" && -w "/config" ]]; then
  if [[ -d "$CONFIG_CA_PATH" ]]; then
    rm -rf "$CONFIG_CA_PATH"
  fi
  cp "$CA_CERT_PATH" "$CONFIG_CA_PATH"
  chmod 644 "$CONFIG_CA_PATH" 2>/dev/null || true

  if [[ -w "$CONFIG_EXPORT_DIR" || ! -e "$CONFIG_EXPORT_DIR" ]]; then
    mkdir -p "$CONFIG_EXPORT_DIR"
    cp "$CA_CERT_PATH" "$CONFIG_EXPORT_CA_PATH"
    chmod 644 "$CONFIG_EXPORT_CA_PATH" 2>/dev/null || true
  fi
fi

if [[ ! -f "$CLUSTER_ID_PATH" ]]; then
  kafka-storage random-uuid > "$CLUSTER_ID_PATH"
  chmod 644 "$CLUSTER_ID_PATH"
  echo "Generated cluster id in $CLUSTER_ID_PATH"
else
  echo "Cluster id already exists in $CLUSTER_ID_PATH"
fi

# Write credential files used by the Kafka container
printf '%s' "$KSTORE_PASS" > "$SECRETS_DIR/keystore_creds"
printf '%s' "$KEY_PASS" > "$SECRETS_DIR/key_creds"
printf '%s' "$TSTORE_PASS" > "$SECRETS_DIR/truststore_creds"

chmod 640 "$SECRETS_DIR/keystore_creds" "$SECRETS_DIR/key_creds" "$SECRETS_DIR/truststore_creds"

# Ensure the Kafka user can read generated files when running as non-root.
chown "$KAFKA_UID:$KAFKA_GID" \
  "$SECRETS_DIR/keystore_creds" \
  "$SECRETS_DIR/key_creds" \
  "$SECRETS_DIR/truststore_creds" \
  "$CLUSTER_ID_PATH" 2>/dev/null || true

CLIENT_USER="${KAFKA_CLIENT_USERNAME:-admin}"
CLIENT_PASS="${KAFKA_CLIENT_PASSWORD:-admin-secret}"

cat > "$CLIENT_PROPS_PATH" <<EOF
security.protocol=SASL_SSL
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="$CLIENT_USER" password="$CLIENT_PASS";
ssl.truststore.location=/etc/kafka/secrets/kafka.truststore.jks
ssl.truststore.password=$TSTORE_PASS
ssl.endpoint.identification.algorithm=https
EOF

echo "Wrote client properties to $CLIENT_PROPS_PATH"
