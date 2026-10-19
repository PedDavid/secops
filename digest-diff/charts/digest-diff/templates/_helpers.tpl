{{- define "digest-diff.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 55 | trimSuffix "-" -}}
{{- end -}}
{{- define "digest-diff.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 55 | trimSuffix "-" -}}
{{- else if contains (include "digest-diff.name" .) .Release.Name -}}
{{- .Release.Name | trunc 55 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "digest-diff.name" .) | trunc 55 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- define "digest-diff.selectorLabels" -}}
app.kubernetes.io/name: {{ include "digest-diff.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "digest-diff.labels" -}}
{{ include "digest-diff.selectorLabels" . }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "digest-diff.claim" -}}
{{- default (printf "%s-cache" (include "digest-diff.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}
