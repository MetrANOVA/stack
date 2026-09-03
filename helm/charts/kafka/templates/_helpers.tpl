{{- define "kafka.clusterName" -}}
{{- $g := dig "kafka" "clusterName" "" (.Values.global | default dict) -}}
{{- dig "Name" $g (.Values.Cluster | default dict) | default .Release.Name -}}
{{- end }}
