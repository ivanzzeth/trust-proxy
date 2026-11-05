{{- define "trust-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trust-proxy.fullname" -}}
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

{{- define "trust-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trust-proxy.labels" -}}
helm.sh/chart: {{ include "trust-proxy.chart" . }}
{{ include "trust-proxy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels only — never add to these after a release exists. A DaemonSet's
spec.selector is immutable, so a new label here turns every subsequent
`helm upgrade` into an error whose only remedy is deleting the DaemonSet, i.e.
taking every node's egress down to add a label.
*/}}
{{- define "trust-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trust-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "trust-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "trust-proxy.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
镜像引用：有 digest 就用 `repo@sha256:…`，否则回落 `repo:tag`。

为什么 digest 优先：tag 可变。同一个 tag 再推一次，`IfNotPresent` 会让 kubelet
继续用节点上缓存的旧层 —— 表现是「发布成功、pod Running、行为却还是旧的」，
而且没有任何东西是红的。digest 让这件事在结构上不可能发生。
形状照抄 ai-sandbox / ai-router。
*/}}
{{- define "trust-proxy.image" -}}
{{- with .Values.image -}}
{{- if .digest -}}
{{ .repository }}@{{ .digest }}
{{- else -}}
{{ .repository }}:{{ .tag | default $.Chart.AppVersion }}
{{- end -}}
{{- end -}}
{{- end -}}
