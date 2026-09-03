{{- define "kafka.clusterName" -}}
{{- $g := dig "global" "kafka" "clusterName" "" .Values -}}
{{- dig "Cluster" "Name" $g .Values | default .Release.Name -}}
{{- end }}
