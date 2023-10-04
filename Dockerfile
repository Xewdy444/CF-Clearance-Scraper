FROM python:slim

WORKDIR /app

COPY . .

RUN apt-get update -y \
    && apt-get install -y \
    libnss3-tools \
    gcc \
    chromium \
    chromium-driver \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir -r requirements.txt \
    && python3 -m seleniumwire extractcert \
    && mkdir -p ${HOME}/.pki/nssdb \
    && certutil -d ${HOME}/.pki/nssdb -N \
    && certutil -d sql:${HOME}/.pki/nssdb -A -t TC -n "Selenium Wire" -i ca.crt \
    && rm ca.crt

ENTRYPOINT [ "python3", "main.py" ]
