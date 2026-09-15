{{- define "telegraf.kafkaNamespace" -}}
{{- .Values.kafka.namespace | default .Release.Namespace -}}
{{- end }}

{{- define "telegraf.kafkaUserSecretName" -}}
{{- .Values.kafka.certSecret | default (.Values.kafka.userName | default "pipeline-user") -}}
{{- end }}

{{- define "telegraf.kafkaClusterCaSecretName" -}}
{{- .Values.kafka.clusterCaSecret | default (printf "%s-cluster-ca-cert" (.Values.kafka.clusterName | default "metranova-kafka")) -}}
{{- end }}

{{- define "telegraf.kafkaBootstrapHost" -}}
{{- printf "%s-kafka-bootstrap.%s.svc" (.Values.kafka.clusterName | default "metranova-kafka") (include "telegraf.kafkaNamespace" .) -}}
{{- end }}

{{- define "telegraf.kafkaOutput" -}}
[[outputs.kafka]]
  brokers = ["{{ include "telegraf.kafkaBootstrapHost" . }}:{{ .Values.kafka.port }}"]
  topic = "{{ .topic }}"
  enable_tls = true
  data_format = "json"
  tls_ca = "/etc/telegraf/cluster-ca/{{ .Values.kafka.clusterCaCert }}"
  tls_cert = "/etc/telegraf/certs/{{ .Values.kafka.userCert }}"
  tls_key = "/etc/telegraf/certs/{{ .Values.kafka.userKey }}"
  namepass = ["{{ .metric }}"]
{{- end }}
