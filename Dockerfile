# ---- builder: fetch the signature db, install deps, precompile bytecode ----
FROM python:3.12-alpine AS builder

RUN apk add --no-cache git \
    && git clone --depth 1 https://github.com/p0f/p0f.git /tmp/p0f-src \
    && cp /tmp/p0f-src/p0f.fp /p0f.fp \
    && rm -rf /tmp/p0f-src

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --target=/deps -r /tmp/requirements.txt

COPY pyp0f /src/pyp0f
# -O matches the optimization level the entrypoint runs with below; compiled
# bytecode is tagged per optimization level, so the flags must agree or the
# interpreter recompiles from source on every container start anyway.
RUN python -O -m compileall -q /deps /src/pyp0f

# ---- final: only what is needed to run ----
FROM python:3.12-alpine

# tcpdump compiles the BPF filter string at startup; libpcap is what scapy
# opens via ctypes for that. The plain "libpcap" package only ships the
# versioned libpcap.so.1 (not the unversioned name ctypes looks for), so a
# symlink is added by hand instead of pulling in the whole -dev package
# (headers, .a, pkgconfig) just for that one link.
RUN apk add --no-cache libpcap tcpdump \
    && ln -s /usr/lib/libpcap.so.1 /usr/lib/libpcap.so

WORKDIR /app
ENV PYP0F_DB_PATH=/app/p0f.fp \
    PYTHONPATH=/app/deps \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=builder /p0f.fp ./p0f.fp
COPY --from=builder /deps ./deps
COPY --from=builder /src/pyp0f ./pyp0f

ENTRYPOINT ["python", "-O", "-m", "pyp0f.main"]
