{{/*
Expand the name of the chart.
*/}}
{{- define "core-graph.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "core-graph.fullname" -}}
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
Chart label helper.
*/}}
{{- define "core-graph.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "core-graph.labels" -}}
helm.sh/chart: {{ include "core-graph.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: core-graph
{{- end }}

{{/*
Selector labels for a specific component.
Usage: {{ include "core-graph.selectorLabels" (dict "Release" .Release "component" "api") }}
*/}}
{{- define "core-graph.selectorLabels" -}}
app.kubernetes.io/name: {{ .component }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component fullname helper.
Usage: {{ include "core-graph.componentName" (dict "Release" .Release "Chart" .Chart "component" "api") }}
*/}}
{{- define "core-graph.componentName" -}}
{{- printf "%s-%s" .Release.Name .component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Standard restricted container security context for non-root containers.
*/}}
{{- define "core-graph.restrictedSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: {{ .readOnlyRootFilesystem | default false }}
runAsNonRoot: true
runAsUser: {{ .runAsUser | default 10001 }}
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Topology spread constraints for prod multi-replica deployments.
*/}}
{{- define "core-graph.topologySpread" -}}
{{- $multiReplica := gt (int .replicaCount) 1 -}}
{{- if and (eq .Values.global.profile "prod") $multiReplica }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        {{- include "core-graph.selectorLabels" (dict "Release" .Release "component" .component) | nindent 8 }}
{{- end }}
{{- end }}

{{/*
Init container: wait for a TCP service to become reachable.
The image is configurable via .Values.global.waitForImage for air-gapped registries.
*/}}
{{- define "core-graph.waitFor" -}}
- name: wait-for-{{ .name }}
  image: {{ .waitForImage | default "busybox:1.37" }}
  command: ['sh', '-c', 'until nc -z {{ .host }} {{ .port }} ; do echo "waiting for {{ .name }}..."; sleep 2; done']
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: 65534
    capabilities:
      drop:
        - ALL
    seccompProfile:
      type: RuntimeDefault
  resources:
    requests:
      cpu: 10m
      memory: 16Mi
    limits:
      cpu: 50m
      memory: 32Mi
{{- end }}

{{/*
Image pull secrets helper.
*/}}
{{- define "core-graph.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Node scheduling: nodeSelector + tolerations from global values.
*/}}
{{- define "core-graph.nodeScheduling" -}}
{{- with .Values.global.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.global.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
PostgreSQL host — resolves to internal service or external host.
*/}}
{{- define "core-graph.postgresHost" -}}
{{- if .Values.postgres.enabled -}}
  {{- include "core-graph.componentName" (dict "Release" .Release "Chart" .Chart "component" "postgres") -}}
{{- else -}}
  {{- required "postgres.external.host is required when postgres.enabled=false" .Values.postgres.external.host -}}
{{- end -}}
{{- end }}

{{/*
PostgreSQL port.
*/}}
{{- define "core-graph.postgresPort" -}}
{{- if .Values.postgres.enabled -}}
  5432
{{- else -}}
  {{- .Values.postgres.external.port | default 5432 -}}
{{- end -}}
{{- end }}

{{/*
PostgreSQL DSN including username, password, host, port, and database.
The full DSN is stored in a Secret so that the password is never exposed
in a ConfigMap. Kubernetes does not interpolate env-var references inside
other env-var values, so the password must be baked into the DSN string.
*/}}
{{- define "core-graph.postgresDSN" -}}
{{- $host := include "core-graph.postgresHost" . -}}
{{- $port := include "core-graph.postgresPort" . -}}
{{- $password := ternary .Values.postgres.auth.password .Values.postgres.external.password .Values.postgres.enabled -}}
{{- printf "postgresql://%s:%s@%s:%s/%s" .Values.postgres.auth.username $password (trimAll " " $host) (trimAll " " $port) .Values.postgres.auth.database -}}
{{- end }}

{{/*
NATS URL — resolves to internal service or external URL.
*/}}
{{- define "core-graph.natsURL" -}}
{{- if .Values.nats.enabled -}}
  {{- printf "nats://%s:4222" (include "core-graph.componentName" (dict "Release" .Release "Chart" .Chart "component" "nats")) -}}
{{- else -}}
  {{- required "nats.external.url is required when nats.enabled=false" .Values.nats.external.url -}}
{{- end -}}
{{- end }}

{{/*
Valkey URL — resolves to internal service or external URL.
*/}}
{{- define "core-graph.valkeyURL" -}}
{{- if .Values.valkey.enabled -}}
  {{- printf "redis://%s:6379" (include "core-graph.componentName" (dict "Release" .Release "Chart" .Chart "component" "valkey")) -}}
{{- else -}}
  {{- required "valkey.external.url is required when valkey.enabled=false" .Values.valkey.external.url -}}
{{- end -}}
{{- end }}
