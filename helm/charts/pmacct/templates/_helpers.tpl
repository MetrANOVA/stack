{{- define "pmacct.kafkaNamespace" -}}
{{- .Values.kafka.namespace | default .Release.Namespace -}}
{{- end }}

{{- define "pmacct.kafkaClusterName" -}}
{{- $g := dig "kafka" "clusterName" "" (.Values.global | default dict) -}}
{{- dig "kafka" "clusterName" $g (.Values.config | default dict) | default .Release.Name -}}
{{- end }}

{{- define "pmacct.kafkaUserSecretName" -}}
{{- .Values.kafka.certSecret | default (.Values.kafka.userName | default "pipeline-user") -}}
{{- end }}

{{- define "pmacct.kafkaClusterCaSecretName" -}}
{{- .Values.kafka.clusterCaSecret | default (printf "%s-cluster-ca-cert" (include "pmacct.kafkaClusterName" .)) -}}
{{- end }}

{{- define "pmacct.kafkaBootstrapHost" -}}
{{- printf "%s-kafka-bootstrap.%s.svc" (include "pmacct.kafkaClusterName" .) (include "pmacct.kafkaNamespace" .) -}}
{{- end }}
