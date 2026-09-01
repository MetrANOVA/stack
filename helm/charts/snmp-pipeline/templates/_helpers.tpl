{{/*
Expand the name of the chart.
*/}}
{{- define "metranova-snmp-pipeline.name" -}}
{{- default .Chart.Name .Values.nameOverride | lower | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "metranova-snmp-pipeline.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | lower | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride | lower }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | lower | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | lower | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "metranova-snmp-pipeline.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "metranova-snmp-pipeline.labels" -}}
helm.sh/chart: {{ include "metranova-snmp-pipeline.chart" . }}
{{ include "metranova-snmp-pipeline.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "metranova-snmp-pipeline.selectorLabels" -}}
app.kubernetes.io/name: {{ include "metranova-snmp-pipeline.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "metranova-snmp-pipeline.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "metranova-snmp-pipeline.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "metranova-snmp-pipeline.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{- define "metranova-snmp-pipeline.kafkaClusterName" -}}
{{- $g := dig "kafka" "clusterName" "" (.Values.global | default dict) -}}
{{- .Values.config.kafka.clusterName | default $g | default .Release.Name -}}
{{- end }}

{{/*
Resolve Kafka bootstrap servers.
*/}}
{{- define "metranova-snmp-pipeline.kafkaBootstrapServers" -}}
{{- if .Values.config.kafka.bootstrapServers -}}
{{- .Values.config.kafka.bootstrapServers -}}
{{- else -}}
{{- printf "%s-kafka-bootstrap:%v" (include "metranova-snmp-pipeline.kafkaClusterName" .) (.Values.config.kafka.port | default 9092) -}}
{{- end -}}
{{- end }}

{{/*
Resolve Kafka cluster CA secret.
*/}}
{{- define "metranova-snmp-pipeline.kafkaClusterCaSecretName" -}}
{{- .Values.config.kafka.clusterCaSecret | default (printf "%s-cluster-ca-cert" (include "metranova-snmp-pipeline.kafkaClusterName" .)) -}}
{{- end }}

{{/*
Resolve ClickHouse service host.
*/}}
{{- define "metranova-snmp-pipeline.clickhouseHost" -}}
{{- if .Values.config.clickhouse.host -}}
{{- .Values.config.clickhouse.host -}}
{{- else -}}
{{- .Values.config.clickhouse.serviceName | default (printf "clickhouse-%s" (dig "clickhouse" "name" "ch-cluster" (.Values.global | default dict))) -}}
{{- end -}}
{{- end }}

{{/*
Resolve Redis service host.
*/}}
{{- define "metranova-snmp-pipeline.redisHost" -}}
{{- if .Values.config.redis.host -}}
{{- .Values.config.redis.host -}}
{{- else -}}
{{- .Values.config.redis.serviceName | default (printf "%s-redis" (include "metranova-snmp-pipeline.fullname" .)) -}}
{{- end -}}
{{- end }}

{{/*
Resolve ClickHouse password secret name.
*/}}
{{- define "metranova-snmp-pipeline.clickhousePasswordSecretName" -}}
{{- $cfg := .Values.config | default dict -}}
{{- $ch := $cfg.clickhouse | default dict -}}
{{- $ps := $ch.passwordSecret | default dict -}}
{{- $ps.name | default (.Values.certificates.existingSecret | default (printf "%s-secrets" (include "metranova-snmp-pipeline.fullname" .))) -}}
{{- end }}

{{/*
Resolve ClickHouse password secret key.
*/}}
{{- define "metranova-snmp-pipeline.clickhousePasswordSecretKey" -}}
{{- $cfg := .Values.config | default dict -}}
{{- $ch := $cfg.clickhouse | default dict -}}
{{- $ps := $ch.passwordSecret | default dict -}}
{{- $ps.key | default "CLICKHOUSE_PASSWORD" -}}
{{- end }}
