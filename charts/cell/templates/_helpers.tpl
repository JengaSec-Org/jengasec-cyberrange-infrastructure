{{- define "cell.name" -}}{{ .Values.cell }}{{- end -}}
{{- define "cell.labels" -}}
app.kubernetes.io/name: {{ .Values.cell }}
app.kubernetes.io/part-of: jengasec
jengasec.io/cell: {{ .Values.cell }}
jengasec.io/enterprise: {{ .Values.enterprise }}
{{- end -}}
