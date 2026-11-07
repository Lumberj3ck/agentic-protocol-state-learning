# Paramiko server SUT (stream B1). Dockerfile adapted from vendor/agentic-protocol-state-learning/targets/paramiko (Apache-2.0).
FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
RUN pip install --no-cache-dir paramiko==5.1.0 && mkdir -p /etc/psm
COPY server.py /server.py
EXPOSE 22
CMD ["python", "-u", "/server.py"]
