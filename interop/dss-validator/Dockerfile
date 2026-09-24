# OpenSSL + xmlsec1 + pyhanko validator for PAdES/CAdES/XAdES interop testing.
#
# Validates CMS/PKCS#7 signatures using OpenSSL, XML signatures with xmlsec1,
# and PAdES signatures with pyHanko.
#
# Usage:
#   docker build -t simplesign-dss interop/dss-validator
#   docker run --rm -v /path/to/files:/in simplesign-dss validate-cms /in/signature.p7s /in/data.bin /in/cert.pem
#   docker run --rm -v /path/to/files:/in simplesign-dss validate-pades /in/signed.pdf

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache \
        "openssl=3.5.8-r0" \
        "bash=5.3.9-r1" \
        "xmlsec=1.3.11-r0" \
        "python3=3.14.7-r1" \
        "py3-pip=26.1.2-r0" \
        "tzdata=2026d-r0"

COPY requirements.txt /opt/requirements.txt
RUN pip3 install --break-system-packages -r /opt/requirements.txt

COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
