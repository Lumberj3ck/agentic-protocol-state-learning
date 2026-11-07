FROM python:3.12-slim
RUN pip install --no-cache-dir paramiko==5.1.0
COPY server.py /server.py
EXPOSE 22
CMD ["python", "/server.py"]
