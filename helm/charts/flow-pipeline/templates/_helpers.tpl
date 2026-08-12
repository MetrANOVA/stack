{{/*
Expand the name of the chart.
*/}}
{{- define "metranova-flow-pipeline.name" -}}
{{- default .Chart.Name .Values.nameOverride | lower | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "metranova-flow-pipeline.fullname" -}}
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
{{- define "metranova-flow-pipeline.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "metranova-flow-pipeline.labels" -}}
helm.sh/chart: {{ include "metranova-flow-pipeline.chart" . }}
{{ include "metranova-flow-pipeline.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "metranova-flow-pipeline.selectorLabels" -}}
app.kubernetes.io/name: {{ include "metranova-flow-pipeline.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "metranova-flow-pipeline.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "metranova-flow-pipeline.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "metranova-flow-pipeline.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Resolve Kafka bootstrap servers.
*/}}
{{- define "metranova-flow-pipeline.kafkaBootstrapServers" -}}
{{- if .Values.config.kafka.bootstrapServers -}}
{{- .Values.config.kafka.bootstrapServers -}}
{{- else -}}
{{- printf "%s-kafka-bootstrap:%v" (.Values.config.kafka.clusterName | default .Release.Name) (.Values.config.kafka.port | default 9092) -}}
{{- end -}}
{{- end }}

{{/*
Resolve Kafka cluster CA secret.
*/}}
{{- define "metranova-flow-pipeline.kafkaClusterCaSecretName" -}}
{{- .Values.config.kafka.clusterCaSecret | default (printf "%s-cluster-ca-cert" (.Values.config.kafka.clusterName | default .Release.Name)) -}}
{{- end }}

{{/*
Resolve ClickHouse service host.
*/}}
{{- define "metranova-flow-pipeline.clickhouseHost" -}}
{{- if .Values.config.clickhouse.host -}}
{{- .Values.config.clickhouse.host -}}
{{- else -}}
{{- .Values.config.clickhouse.serviceName | default "clickhouse-ch-cluster" -}}
{{- end -}}
{{- end }}

{{/*
Resolve config volume source.
*/}}
{{- define "metranova-flow-pipeline.configVolumeSource" -}}
{{- if .Values.configFiles.existingConfigMap }}
configMap:
  name: {{ .Values.configFiles.existingConfigMap }}
{{- else }}
projected:
  sources:
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-core
{{- if .Values.configFiles.metaInterface }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-meta-interface
{{- end }}
{{- if .Values.configFiles.metaDevice }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-meta-device
{{- end }}
{{- if .Values.configFiles.metaCircuit }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-meta-circuit
{{- end }}
{{- if or .Values.configFiles.metaApplication (.Files.Get "files/meta_application.yml") }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-meta-application
{{- end }}
{{- if .Values.configFiles.caidaAsOrg2Info }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-caida-as-org
{{- end }}
{{- if .Values.configFiles.caidaPeeringDb }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-caida-peeringdb
{{- end }}
{{- if .Values.configFiles.caidaCustomOrgAdditions }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-caida-custom-org
{{- end }}
{{- if .Values.configFiles.caidaCustomAsAdditions }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-caida-custom-as
{{- end }}
{{- if .Values.configFiles.ipgeoCustomIpFile }}
    - configMap:
        name: {{ include "metranova-flow-pipeline.fullname" . }}-config-ipgeo-custom-ip
{{- end }}
{{- end }}
{{- end }}

{{/*
Resolve ClickHouse password secret name.
*/}}
{{- define "metranova-flow-pipeline.clickhousePasswordSecretName" -}}
{{- $cfg := .Values.config | default dict -}}
{{- $ch := $cfg.clickhouse | default dict -}}
{{- $ps := $ch.passwordSecret | default dict -}}
{{- $ps.name | default (.Values.certificates.existingSecret | default (printf "%s-secrets" (include "metranova-flow-pipeline.fullname" .))) -}}
{{- end }}

{{/*
Resolve ClickHouse password secret key.
*/}}
{{- define "metranova-flow-pipeline.clickhousePasswordSecretKey" -}}
{{- $cfg := .Values.config | default dict -}}
{{- $ch := $cfg.clickhouse | default dict -}}
{{- $ps := $ch.passwordSecret | default dict -}}
{{- $ps.key | default "CLICKHOUSE_PASSWORD" -}}
{{- end }}
