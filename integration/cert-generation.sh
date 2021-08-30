#!/bin/bash


CERTIFICATES=(
    webapp
    auth-server
)

for name in "${CERTIFICATES[@]}"; do
    mkdir -p secrets/${name}

    openssl req -x509 -out secrets/${name}/certificate.crt \
        -keyout secrets/${name}/certificate.key \
        -newkey rsa:2048 -nodes -sha256 \
        -subj '/CN=${name}.dev.local' -extensions EXT -config config/cert-${name}.conf
done
