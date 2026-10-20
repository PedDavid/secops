{{- define "digest-diff-2.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 55 | trimSuffix "-" -}}
{{- end -}}
{{- define "digest-diff-2.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 55 | trimSuffix "-" -}}
{{- else if contains (include "digest-diff-2.name" .) .Release.Name -}}
{{- .Release.Name | trunc 55 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "digest-diff-2.name" .) | trunc 55 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- define "digest-diff-2.selectorLabels" -}}
app.kubernetes.io/name: {{ include "digest-diff-2.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "digest-diff-2.labels" -}}
{{ include "digest-diff-2.selectorLabels" . }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "digest-diff-2.claim" -}}
{{- default (printf "%s-cache" (include "digest-diff-2.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}

{{- define "digest-diff-2.cookieSecret" -}}
{{- default (printf "%s-cookie" (include "digest-diff-2.fullname" .)) .Values.cookieKey.existingSecret -}}
{{- end -}}
