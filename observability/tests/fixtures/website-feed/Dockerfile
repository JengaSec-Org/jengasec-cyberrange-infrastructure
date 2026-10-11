FROM python:3.11.14-slim-bookworm

WORKDIR /app

RUN addgroup --system app \
    && adduser --system --ingroup app --no-create-home app \
    && install --directory --owner=app --group=app /data

COPY --chown=app:app app.py /app/app.py

USER app

EXPOSE 8080

CMD ["python", "-u", "/app/app.py"]
