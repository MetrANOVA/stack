{{- define "kafka.clusterName" -}}
{{- $g := dig "kafka" "clusterName" "" (.Values.global | default dict) -}}
{{- .Values.Cluster.Name | default $g | default .Release.Name -}}
{{- end }}
