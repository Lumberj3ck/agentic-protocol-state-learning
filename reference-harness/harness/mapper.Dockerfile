# Runtime for the published SSH mapper (assist-project/ssh-fuzzer @ vendor/ssh-fuzzer.COMMIT).
# Upstream used python:3.9 (~1 GB); slim is used because the box disk is ~99% full.
FROM python:3.9-slim
RUN pip install --no-cache-dir paramiko==3.5.0 cryptography==43.0.3 bcrypt==4.2.0 pynacl==1.5.0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app:/app/mapper HOME=/home/mapper
WORKDIR /app/mapper
ENTRYPOINT ["python3", "/app/mapper/mapper.py"]
