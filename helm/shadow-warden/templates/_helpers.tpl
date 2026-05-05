{{/*
Expand the name of the chart.
*/}}
{{- define "shadow-warden.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "shadow-warden.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "shadow-warden.labels" -}}
helm.sh/chart: {{ include "shadow-warden.name" . }}-{{ .Chart.Version }}
{{ include "shadow-warden.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "shadow-warden.selectorLabels" -}}
app.kubernetes.io/name: {{ include "shadow-warden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
