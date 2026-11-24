FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim

RUN groupadd -r clouddrift && useradd -r -g clouddrift -d /home/clouddrift -m clouddrift
WORKDIR /app

COPY --from=builder /root/.local /home/clouddrift/.local
COPY --chown=clouddrift:clouddrift . /app

ENV PATH=/home/clouddrift/.local/bin:$PATH
ENV PYTHONPATH=/app

USER clouddrift

ENTRYPOINT ["python3", "-m", "cloud_drift.cli"]
CMD ["--help"]
