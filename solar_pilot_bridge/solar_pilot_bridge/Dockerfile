ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.12-alpine3.20
FROM $BUILD_FROM
COPY bridge.py /bridge.py
CMD ["python3", "/bridge.py"]
