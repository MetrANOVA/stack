{{- define "kafka.clusterName" -}}
{{- get (default dict .Values.cluster) "name" | default .Release.Name -}}
{{- end -}}
