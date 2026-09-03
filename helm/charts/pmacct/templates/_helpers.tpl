{{- define "pmacct.kafkaNamespace" -}}
{{- .Values.kafka.namespace | default .Release.Namespace -}}
{{- end }}

{{- define "pmacct.kafkaClusterName" -}}
{{- $g := dig "global" "kafka" "clusterName" "" .Values -}}
{{- dig "config" "kafka" "clusterName" $g .Values | default .Release.Name -}}
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
