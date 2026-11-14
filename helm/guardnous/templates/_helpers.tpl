{{/*
GuardNous Helm Template Helpers
*/}}

{{- define "guardnous.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "guardnous.fullname" -}}
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

{{- define "guardnous.labels" -}}
helm.sh/chart: {{ include "guardnous.name" . }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "guardnous.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.podLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "guardnous.selectorLabels" -}}
app.kubernetes.io/name: {{ include "guardnous.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Service account name */}}
{{- define "guardnous.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "guardnous.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Secret name — existing or generated */}}
{{- define "guardnous.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "guardnous.fullname" . }}-secrets
{{- end }}
{{- end }}

{{/* Name of the Secret holding connection URLs derived from database.externalUrl / redis.externalUrl */}}
{{- define "guardnous.connectionSecretName" -}}
{{- include "guardnous.fullname" . }}-connections
{{- end }}

{{/* "true" when the bundled PostgreSQL / Redis is the one in use */}}
{{- define "guardnous.bundledDatabase" -}}
{{- if and .Values.database.bundled.enabled (not .Values.database.externalUrl) }}true{{- end }}
{{- end }}
{{- define "guardnous.bundledRedis" -}}
{{- if and .Values.redis.bundled.enabled (not .Values.redis.externalUrl) }}true{{- end }}
{{- end }}

{{/*
database.externalUrl without its scheme, so both driver forms can be built
from one value ("postgresql://", "postgres://" and "postgresql+driver://" are
all accepted).
*/}}
{{- define "guardnous.databaseTail" -}}
{{- regexReplaceAll "^[A-Za-z][A-Za-z0-9+.-]*://" .Values.database.externalUrl "" -}}
{{- end }}

{{/*
DATABASE_URL — async driver (asyncpg). asyncpg names the TLS parameter "ssl",
libpq/psycopg2 names it "sslmode", so it is renamed here.
In bundled mode $(DATABASE_PASSWORD) is expanded by Kubernetes from the env
entry of that name, which must come first in the container's env list.
*/}}
{{- define "guardnous.databaseUrl" -}}
{{- if .Values.database.externalUrl -}}
{{- printf "postgresql+asyncpg://%s" (include "guardnous.databaseTail" . | replace "sslmode=" "ssl=") -}}
{{- else -}}
{{- printf "postgresql+asyncpg://guardnous:$(DATABASE_PASSWORD)@%s-postgres:5432/guardnous" (include "guardnous.fullname" .) -}}
{{- end -}}
{{- end }}

{{/* DATABASE_URL_SYNC — psycopg2 driver (migrations, Celery tasks) */}}
{{- define "guardnous.databaseUrlSync" -}}
{{- if .Values.database.externalUrl -}}
{{- printf "postgresql+psycopg2://%s" (include "guardnous.databaseTail" .) -}}
{{- else -}}
{{- printf "postgresql+psycopg2://guardnous:$(DATABASE_PASSWORD)@%s-postgres:5432/guardnous" (include "guardnous.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Redis URL for one logical database. Call with (dict "ctx" . "db" "0").
For an external URL any database number in redis.externalUrl is replaced and
a query string (e.g. ?ssl_cert_reqs=required) is kept.
*/}}
{{- define "guardnous.redisDbUrl" -}}
{{- $ctx := .ctx -}}
{{- if $ctx.Values.redis.externalUrl -}}
{{- $url := $ctx.Values.redis.externalUrl -}}
{{- $query := regexFind "\\?.*$" $url -}}
{{- $base := regexReplaceAll "\\?.*$" $url "" | trimSuffix "/" -}}
{{- $base = regexReplaceAll "/[0-9]+$" $base "" -}}
{{- printf "%s/%s%s" $base .db $query -}}
{{- else -}}
{{- printf "redis://%s-redis:6379/%s" (include "guardnous.fullname" $ctx) .db -}}
{{- end -}}
{{- end }}

{{/* REDIS_URL (db 0), CELERY_BROKER_URL (db 1), CELERY_RESULT_BACKEND (db 2) */}}
{{- define "guardnous.redisUrl" -}}
{{- include "guardnous.redisDbUrl" (dict "ctx" . "db" "0") -}}
{{- end }}
{{- define "guardnous.celeryBrokerUrl" -}}
{{- .Values.redis.celeryBrokerUrl | default (include "guardnous.redisDbUrl" (dict "ctx" . "db" "1")) -}}
{{- end }}
{{- define "guardnous.celeryResultBackend" -}}
{{- .Values.redis.celeryResultBackend | default (include "guardnous.redisDbUrl" (dict "ctx" . "db" "2")) -}}
{{- end }}

{{/* Public address of the installation: the Ingress host when Ingress is on */}}
{{- define "guardnous.publicUrl" -}}
{{- if .Values.ingress.enabled -}}
{{- printf "%s://%s" (ternary "https" "http" .Values.ingress.tls.enabled) .Values.ingress.host -}}
{{- end -}}
{{- end }}
{{- define "guardnous.frontendUrl" -}}
{{- .Values.config.frontendUrl | default (include "guardnous.publicUrl" .) | default "http://localhost:7003" -}}
{{- end }}
{{- define "guardnous.backendUrl" -}}
{{- .Values.config.backendUrl | default (include "guardnous.publicUrl" .) | default "http://localhost:7002" -}}
{{- end }}
{{- define "guardnous.corsOrigins" -}}
{{- .Values.config.corsOrigins | default (include "guardnous.frontendUrl" .) -}}
{{- end }}

{{/* Stops `helm install/upgrade/template` with a clear message when required values are missing */}}
{{- define "guardnous.validate" -}}
{{- if and .Values.database.externalUrl .Values.database.bundled.enabled -}}
{{- fail "database: set either database.externalUrl or database.bundled.enabled=true, not both" -}}
{{- end -}}
{{- if and .Values.redis.externalUrl .Values.redis.bundled.enabled -}}
{{- fail "redis: set either redis.externalUrl or redis.bundled.enabled=true, not both" -}}
{{- end -}}
{{- if not (or .Values.database.externalUrl .Values.database.bundled.enabled .Values.secrets.existingSecret) -}}
{{- fail "database is not configured: set database.externalUrl (postgresql://user:pass@host:5432/db), or database.bundled.enabled=true, or provide DATABASE_URL and DATABASE_URL_SYNC in secrets.existingSecret" -}}
{{- end -}}
{{- if not (or .Values.redis.externalUrl .Values.redis.bundled.enabled .Values.secrets.existingSecret) -}}
{{- fail "redis is not configured: set redis.externalUrl (redis://host:6379), or redis.bundled.enabled=true, or provide REDIS_URL, CELERY_BROKER_URL and CELERY_RESULT_BACKEND in secrets.existingSecret" -}}
{{- end -}}
{{- if not .Values.secrets.existingSecret -}}
{{- if or (not .Values.secrets.secretKey) (contains "change-me" (lower .Values.secrets.secretKey)) -}}
{{- fail "secrets.secretKey is not set (generate one: openssl rand -hex 32), or use secrets.existingSecret" -}}
{{- end -}}
{{- if ne (len .Values.secrets.encryptionKey) 44 -}}
{{- fail "secrets.encryptionKey must be a 44-character Fernet key (generate one: openssl rand -base64 32 | tr '+/' '-_'), or use secrets.existingSecret" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* envFrom for the backend containers (api, worker, beat, database preparation) */}}
{{- define "guardnous.backendEnvFrom" -}}
envFrom:
  - configMapRef:
      name: {{ include "guardnous.fullname" . }}-config
  - secretRef:
      name: {{ include "guardnous.secretName" . }}
  {{- if or .Values.database.externalUrl .Values.redis.externalUrl }}
  - secretRef:
      name: {{ include "guardnous.connectionSecretName" . }}
  {{- end }}
{{- end }}

{{/*
env for the backend containers: connection settings for the bundled
PostgreSQL / Redis. With external services these come from the connections
Secret (or from secrets.existingSecret) through envFrom instead.
Entries in env take precedence over envFrom.
*/}}
{{- define "guardnous.backendEnv" -}}
{{- if or (include "guardnous.bundledDatabase" .) (include "guardnous.bundledRedis" .) -}}
env:
  {{- if include "guardnous.bundledDatabase" . }}
  - name: DATABASE_PASSWORD
    valueFrom:
      secretKeyRef:
        name: {{ include "guardnous.secretName" . }}
        key: DATABASE_PASSWORD
  - name: DATABASE_URL
    value: {{ include "guardnous.databaseUrl" . | quote }}
  - name: DATABASE_URL_SYNC
    value: {{ include "guardnous.databaseUrlSync" . | quote }}
  {{- end }}
  {{- if include "guardnous.bundledRedis" . }}
  - name: REDIS_URL
    value: {{ include "guardnous.redisUrl" . | quote }}
  - name: CELERY_BROKER_URL
    value: {{ include "guardnous.celeryBrokerUrl" . | quote }}
  - name: CELERY_RESULT_BACKEND
    value: {{ include "guardnous.celeryResultBackend" . | quote }}
  {{- end }}
{{- end }}
{{- end }}

{{/* Container securityContext for the backend image (its user "appuser" has UID 1000) */}}
{{- define "guardnous.backendSecurityContext" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: {{ .Values.securityContext.backendUser }}
  readOnlyRootFilesystem: false
  allowPrivilegeEscalation: false
{{- end }}

{{/* Optional shared scanner-binary cache (pluginCache.existingClaim) */}}
{{- define "guardnous.pluginCacheMount" -}}
{{- if .Values.pluginCache.existingClaim -}}
volumeMounts:
  - name: plugin-cache
    mountPath: /app/data/plugin_cache
{{- end }}
{{- end }}
{{- define "guardnous.pluginCacheVolume" -}}
{{- if .Values.pluginCache.existingClaim -}}
securityContext:
  fsGroup: {{ .Values.securityContext.backendUser }}
volumes:
  - name: plugin-cache
    persistentVolumeClaim:
      claimName: {{ .Values.pluginCache.existingClaim }}
{{- end }}
{{- end }}

{{/* Common pod spec fields */}}
{{- define "guardnous.podSpec" -}}
serviceAccountName: {{ include "guardnous.serviceAccountName" . }}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/* Resolve image with optional global registry */}}
{{- define "guardnous.image" -}}
{{- $repo := .image.repository -}}
{{- if .global.imageRegistry -}}
{{- printf "%s/%s:%s" .global.imageRegistry $repo (.image.tag | default "latest") -}}
{{- else -}}
{{- printf "%s:%s" $repo (.image.tag | default "latest") -}}
{{- end -}}
{{- end }}
