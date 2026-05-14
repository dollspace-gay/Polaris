{{/*
Helper templates for the Polaris chart.

These keep the resource templates in this chart consistent on labels,
selectors, and the fully-qualified release name. They follow the
upstream Bitnami `_helpers.tpl` shape so an operator who has worked
with bitnami/postgresql or bitnami/redis can read this chart without a
context switch.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "polaris.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited
to that length (RFC 1123 label).
*/}}
{{- define "polaris.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels (kubernetes.io/* recommended labels).
*/}}
{{- define "polaris.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "polaris.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: backend
{{- end -}}

{{/*
Selector labels (a stable subset of the labels above — pod selectors
must not include version, so a rolling update does not change the
selector and orphan the existing ReplicaSet).
*/}}
{{- define "polaris.selectorLabels" -}}
app.kubernetes.io/name: {{ include "polaris.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
