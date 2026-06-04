{{/*
Expand the name of the chart.
*/}}
{{- define "metranova-auth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "metranova-auth.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "metranova-auth.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "metranova-auth.labels" -}}
helm.sh/chart: {{ include "metranova-auth.chart" . }}
{{ include "metranova-auth.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "metranova-auth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "metranova-auth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "metranova-auth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "metranova-auth.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image pull secrets block
*/}}
{{- define "metranova-auth.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Derive LDAP base DN from ldap.domain ("metranova.io" → "dc=metranova,dc=io")
*/}}
{{- define "metranova-auth.ldapBaseDN" -}}
{{- $parts := splitList "." .Values.ldap.domain -}}
{{- range $i, $p := $parts -}}{{- if $i }},{{ end }}dc={{ $p }}{{- end -}}
{{- end }}

{{/*
Name of the secret that holds TLS cert/key for Envoy
*/}}
{{- define "metranova-auth.tlsSecretName" -}}
{{- if .Values.envoy.tls.existingTLSSecret -}}
{{ .Values.envoy.tls.existingTLSSecret }}
{{- else -}}
{{ include "metranova-auth.fullname" . }}-tls
{{- end -}}
{{- end }}
