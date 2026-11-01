{{/* The chart's name. */}}
{{- define "agent.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The name of the agent's objects: the release name when it holds the chart's name (helm install nslookup-agent …),
else <release>-agent.
*/}}
{{- define "agent.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "agent.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "agent.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
What the agent may do in a namespace (or in every one): read Ingresses, read and write Secrets. It never writes an
Ingress, never lists or deletes a Secret, and needs nothing else.
*/}}
{{- define "agent.rules" -}}
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "create", "update", "patch"]
{{- end -}}

{{/* The namespaces the agent is limited to, each once, as JSON (an empty list: every namespace). */}}
{{- define "agent.namespaces" -}}
{{- $namespaces := .Values.namespaces | default list -}}
{{- if not (kindIs "slice" $namespaces) -}}
{{- fail "namespaces is a list, for example --set \"namespaces={shop,blog}\"" -}}
{{- end -}}
{{- range $namespaces -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$" (toString .)) -}}
{{- fail (printf "namespaces: %q is not a namespace name" (toString .)) -}}
{{- end -}}
{{- end -}}
{{- $namespaces | uniq | toJson -}}
{{- end -}}
