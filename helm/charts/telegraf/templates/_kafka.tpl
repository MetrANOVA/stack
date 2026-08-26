{{- define "telegraf.kafkaNamespace" -}}
{{- .Values.kafka.namespace | default .Release.Namespace -}}
{{- end }}

{{- define "telegraf.kafkaUserSecretName" -}}
{{- .Values.kafka.certSecret | default (.Values.kafka.userName | default "pipeline-user") -}}
{{- end }}

{{- define "telegraf.kafkaClusterCaSecretName" -}}
{{- .Values.kafka.clusterCaSecret | default (printf "%s-cluster-ca-cert" (.Values.kafka.clusterName | default .Release.Name)) -}}
{{- end }}

{{- define "telegraf.kafkaBootstrapHost" -}}
{{- printf "%s-kafka-bootstrap.%s.svc" (.Values.kafka.clusterName | default .Release.Name) (include "telegraf.kafkaNamespace" .) -}}
{{- end }}

{{- define "telegraf.kafkaBrokers" -}}
{{- if .Values.outputs.kafka.brokers -}}
{{- .Values.outputs.kafka.brokers | toJson -}}
{{- else -}}
{{- list (printf "%s:%v" (include "telegraf.kafkaBootstrapHost" .) .Values.kafka.port) | toJson -}}
{{- end -}}
{{- end }}

{{- define "telegraf.kafkaOutputs" -}}
{{- $root := . -}}
{{- range .Values.outputs.kafka.topics }}
[[outputs.kafka]]
  brokers = {{ include "telegraf.kafkaBrokers" $root }}
  topic = "{{ .topic }}"
  data_format = "{{ $root.Values.outputs.kafka.dataFormat }}"
{{- if $root.Values.outputs.kafka.tls.enabled }}
  enable_tls = true
  tls_ca = "/etc/telegraf/cluster-ca/{{ $root.Values.kafka.clusterCaCert }}"
  tls_cert = "/etc/telegraf/certs/{{ $root.Values.kafka.userCert }}"
  tls_key = "/etc/telegraf/certs/{{ $root.Values.kafka.userKey }}"
{{- end }}
{{- with .namepass }}
  namepass = {{ toJson . }}
{{- end }}
{{- end }}
{{- end }}
