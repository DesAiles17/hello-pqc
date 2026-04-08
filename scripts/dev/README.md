# Dev Helpers

- [`docker-build.sh`](/home/denys/hello-pqc/scripts/dev/docker-build.sh): build Docker service images
- [`gen_keys.sh`](/home/denys/hello-pqc/scripts/dev/gen_keys.sh): generate local cryptographic keys from one entrypoint, with optional `--algorithms` filtering
- [`reset-db.sh`](/home/denys/hello-pqc/scripts/dev/reset-db.sh): reset the Postgres volume in the local stack
- [`generate_tls_certs.sh`](/home/denys/hello-pqc/scripts/dev/generate_tls_certs.sh): generate local CA and service TLS certificates

Compatibility wrappers remain at:

- [`docker-build.sh`](/home/denys/hello-pqc/docker-build.sh)
- [`gen_keys.sh`](/home/denys/hello-pqc/gen_keys.sh)
- [`reset-db.sh`](/home/denys/hello-pqc/reset-db.sh)
- [`scripts/generate_tls_certs.sh`](/home/denys/hello-pqc/scripts/generate_tls_certs.sh)
