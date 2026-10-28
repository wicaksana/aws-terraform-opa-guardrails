FROM python:3.13-slim

WORKDIR /app
COPY app.py .

USER nobody
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"]

CMD ["python", "app.py"]
