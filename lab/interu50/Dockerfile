FROM python:3.13-slim
WORKDIR /app
COPY server.py /app/server.py
COPY index.html /app/index.html
USER 65534:65534
EXPOSE 3000
CMD ["python", "-B", "/app/server.py"]
