FROM python:3.11-slim

WORKDIR /app

# gosu für privilege drop in entrypoint, msitools für MSI-Metadaten-Parsing,
# dann non-root User
RUN apt-get update \
 && apt-get install -y --no-install-recommends gosu msitools \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 1001 -s /usr/sbin/nologin softshelf

# Abhängigkeiten zuerst (besseres Layer-Caching)
COPY proxy/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App-Code
COPY proxy/ .
RUN chmod +x /app/entrypoint.sh

EXPOSE 8765

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8765"]
