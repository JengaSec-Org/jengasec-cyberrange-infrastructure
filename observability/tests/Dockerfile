FROM python:3.11.14-slim-bookworm

COPY observability/tests/requirements.txt /tmp/requirements.txt

RUN pip install \
    --disable-pip-version-check \
    --no-cache-dir \
    --root-user-action=ignore \
    --requirement /tmp/requirements.txt

WORKDIR /workspace

ENTRYPOINT ["bash", "observability/tests/test-contracts.sh"]
