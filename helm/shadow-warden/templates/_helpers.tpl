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
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "shadow-warden.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "shadow-warden.labels" -}}
helm.sh/chart: {{ include "shadow-warden.chart" . }}
{{ include "shadow-warden.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "shadow-warden.selectorLabels" -}}
app.kubernetes.io/name: {{ include "shadow-warden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-specific selector labels
*/}}
{{- define "shadow-warden.componentLabels" -}}
{{ include "shadow-warden.selectorLabels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "shadow-warden.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "shadow-warden.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "shadow-warden.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Full image reference with optional registry prefix
*/}}
{{- define "shadow-warden.image" -}}
{{- $registry := .Values.global.imageRegistry -}}
{{- $repo := .image.repository -}}
{{- $tag  := .image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{ printf "%s/%s:%s" $registry $repo $tag }}
{{- else -}}
{{ printf "%s:%s" $repo $tag }}
{{- end }}
{{- end }}

{{/*
PostgreSQL host — bundled or external
*/}}
{{- define "shadow-warden.postgresqlHost" -}}
{{- if .Values.postgresql.enabled -}}
{{ include "shadow-warden.fullname" . }}-postgresql
{{- else -}}
{{ .Values.externalPostgresql.host }}
{{- end }}
{{- end }}

{{/*
PostgreSQL connection string
*/}}
{{- define "shadow-warden.databaseUrl" -}}
{{- if .Values.postgresql.enabled -}}
postgresql://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ include "shadow-warden.postgresqlHost" . }}:5432/{{ .Values.postgresql.auth.database }}
{{- else -}}
postgresql://{{ .Values.externalPostgresql.username }}:$(POSTGRES_PASSWORD)@{{ .Values.externalPostgresql.host }}:{{ .Values.externalPostgresql.port }}/{{ .Values.externalPostgresql.database }}
{{- end }}
{{- end }}

{{/*
Redis URL — bundled or external
*/}}
{{- define "shadow-warden.redisUrl" -}}
{{- if .Values.redis.enabled -}}
redis://:$(REDIS_PASSWORD)@{{ include "shadow-warden.fullname" . }}-redis-master:6379/0
{{- else -}}
redis://:$(REDIS_PASSWORD)@{{ .Values.externalRedis.host }}:{{ .Values.externalRedis.port }}/0
{{- end }}
{{- end }}

{{/*
PostgreSQL password — bundled or external
*/}}
{{- define "shadow-warden.postgresqlPassword" -}}
{{- if .Values.postgresql.enabled -}}
{{- .Values.postgresql.auth.password -}}
{{- else -}}
{{- .Values.externalPostgresql.password -}}
{{- end -}}
{{- end }}

{{/*
Redis password — bundled or external
*/}}
{{- define "shadow-warden.redisPassword" -}}
{{- if .Values.redis.enabled -}}
{{- .Values.redis.auth.password -}}
{{- else -}}
{{- .Values.externalRedis.password -}}
{{- end -}}
{{- end }}
