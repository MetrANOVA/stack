#!/usr/bin/env bash
set -euo pipefail

SECRETS_DIR="/etc/kafka/secrets"
KEYSTORE_PATH="$SECRETS_DIR/kafka.keystore.jks"
TRUSTSTORE_PATH="$SECRETS_DIR/kafka.truststore.jks"
CLIENT_PROPS_PATH="${KAFKA_CLIENT_PROPERTIES_PATH:-/config/client.properties}"
CLUSTER_ID_PATH="$SECRETS_DIR/cluster_id"

KSTORE_PASS="${KAFKA_SSL_KEYSTORE_PASSWORD:-changeit}"
TSTORE_PASS="${KAFKA_SSL_TRUSTSTORE_PASSWORD:-changeit}"
KEY_PASS="${KAFKA_SSL_KEY_PASSWORD:-changeit}"
DNS_NAME="${KAFKA_SSL_DNS_NAME:-kafka}"

if [[ ! -f "$KEYSTORE_PATH" || ! -f "$TRUSTSTORE_PATH" ]]; then
  WORKDIR="/tmp/kafka-certs"
  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"

  # Create a local CA
  openssl req -new -x509 \
    -keyout "$WORKDIR/ca.key" \
    -out "$WORKDIR/ca.crt" \
    -days 3650 \
    -passout pass:"$TSTORE_PASS" \
    -subj "/CN=Kafka-Local-CA"

  # Create broker keystore and CSR
  keytool -genkeypair \
    -alias kafka \
    -keystore "$KEYSTORE_PATH" \
    -storepass "$KSTORE_PASS" \
    -keypass "$KEY_PASS" \
    -dname "CN=$DNS_NAME, OU=Dev, O=Local, L=Local, S=Local, C=US" \
    -ext SAN=DNS:"$DNS_NAME",IP:127.0.0.1 \
    -validity 3650

  keytool -certreq \
    -alias kafka \
    -keystore "$KEYSTORE_PATH" \
    -storepass "$KSTORE_PASS" \
    -file "$WORKDIR/kafka.csr"

  # Sign the broker cert with the local CA
  openssl x509 -req \
    -CA "$WORKDIR/ca.crt" \
    -CAkey "$WORKDIR/ca.key" \
    -in "$WORKDIR/kafka.csr" \
    -out "$WORKDIR/kafka.crt" \
    -days 3650 \
    -CAcreateserial \
    -passin pass:"$TSTORE_PASS"

  # Create truststore with CA cert
  keytool -importcert \
    -alias CARoot \
    -file "$WORKDIR/ca.crt" \
    -keystore "$TRUSTSTORE_PATH" \
    -storepass "$TSTORE_PASS" \
    -noprompt

  # Import CA and broker cert into keystore
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

if [[ ! -f "$CLUSTER_ID_PATH" ]]; then
  kafka-storage random-uuid > "$CLUSTER_ID_PATH"
  chmod 600 "$CLUSTER_ID_PATH"
  echo "Generated cluster id in $CLUSTER_ID_PATH"
else
  echo "Cluster id already exists in $CLUSTER_ID_PATH"
fi

# Write credential files used by the Kafka container
printf '%s' "$KSTORE_PASS" > "$SECRETS_DIR/keystore_creds"
printf '%s' "$KEY_PASS" > "$SECRETS_DIR/key_creds"
printf '%s' "$TSTORE_PASS" > "$SECRETS_DIR/truststore_creds"

chmod 600 "$SECRETS_DIR/keystore_creds" "$SECRETS_DIR/key_creds" "$SECRETS_DIR/truststore_creds"

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
