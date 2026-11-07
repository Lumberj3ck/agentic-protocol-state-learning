FROM python:3.12-slim
RUN pip install --no-cache-dir asyncssh==2.17.0
COPY server.py /server.py
EXPOSE 22
CMD ["python", "/server.py"]
