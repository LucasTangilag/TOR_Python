FROM python:3.14-slim
WORKDIR /app
RUN pip install cryptography
COPY client.py server.py ./
