{{- define "pmacct.kafkaNamespace" -}}
{{- .Values.kafka.namespace | default .Release.Namespace -}}
{{- end }}

{{- define "pmacct.kafkaUserSecretName" -}}
{{- .Values.kafka.certSecret | default (.Values.kafka.userName | default "pipeline-user") -}}
{{- end }}

{{- define "pmacct.kafkaClusterCaSecretName" -}}
{{- .Values.kafka.clusterCaSecret | default (printf "%s-cluster-ca-cert" (.Values.kafka.clusterName | default .Release.Name)) -}}
{{- end }}

{{- define "pmacct.kafkaBootstrapHost" -}}
{{- printf "%s-kafka-bootstrap.%s.svc" (.Values.kafka.clusterName | default .Release.Name) (include "pmacct.kafkaNamespace" .) -}}
{{- end }}
