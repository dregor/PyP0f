FROM python:3.12-alpine

# tcpdump is used by scapy to compile the BPF filter string; libpcap is the
# runtime capture library.
RUN apk add --no-cache libpcap libpcap-dev tcpdump \
    && apk add --no-cache --virtual .build-deps git \
    && git clone --depth 1 https://github.com/p0f/p0f.git /tmp/p0f-src \
    && cp /tmp/p0f-src/p0f.fp /app-p0f.fp \
    && rm -rf /tmp/p0f-src \
    && apk del .build-deps

WORKDIR /app
ENV PYP0F_DB_PATH=/app-p0f.fp

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyp0f ./pyp0f

ENTRYPOINT ["python", "-m", "pyp0f.main"]
