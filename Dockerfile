FROM python:3.12-alpine
WORKDIR /app
COPY . .
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1
CMD ["python", "panos_emulator.py"]
