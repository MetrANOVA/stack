{{- define "kafka.clusterName" -}}
{{- $g := dig "kafka" "clusterName" "" (.Values.global | default dict) -}}
{{- dig "name" $g (.Values.cluster | default dict) | default .Release.Name -}}
{{- end }}

{{/*
Name of the external SCRAM/mTLS user. Defaults to <clusterName>-external-user.
Strimzi's User Operator creates a Secret of the same name holding the
generated password (scram-sha-512) or client cert (tls).
*/}}
{{- define "kafka.externalUserName" -}}
{{- .Values.external.user.name | default (printf "%s-external-user" (include "kafka.clusterName" .)) -}}
{{- end }}
