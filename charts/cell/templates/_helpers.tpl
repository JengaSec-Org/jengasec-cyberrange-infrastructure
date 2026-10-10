{{- define "cell.name" -}}{{ .Values.namespace }}{{- end -}}
{{- define "cell.labels" -}}
app.kubernetes.io/name: {{ .Values.application | lower }}
app.kubernetes.io/part-of: jengasec
jengasec.io/application: {{ .Values.application | quote }}
jengasec.io/enterprise: {{ .Values.enterprise }}
{{- end -}}
