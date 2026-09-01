{{- define "clickhouse.chkName" -}}
{{- .Values.config.chk.name | default (printf "%s-clickhouse-keeper" .Release.Name) -}}
{{- end }}

{{- define "clickhouse.chkClusterName" -}}
{{- .Values.config.chk.clusterName | default (include "clickhouse.chkName" .) -}}
{{- end }}

{{- define "clickhouse.chkHost" -}}
{{- printf "chk-%s-%s-0-%d" (include "clickhouse.chkName" .root) (include "clickhouse.chkClusterName" .root) .replica -}}
{{- end }}

{{- define "clickhouse.chiName" -}}
{{- .Values.config.ch.name | default (printf "%s-clickhouse" .Release.Name) -}}
{{- end }}

{{- define "clickhouse.serviceName" -}}
{{- printf "clickhouse-%s" (include "clickhouse.chiName" .) -}}
{{- end }}

