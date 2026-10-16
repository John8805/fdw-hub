FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client autossh \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "psycopg[binary]>=3.1,<4" "pyyaml>=6" "cryptography>=42"
WORKDIR /app
COPY hubctl.py /app/hubctl.py
ENTRYPOINT ["python", "-u", "/app/hubctl.py"]
