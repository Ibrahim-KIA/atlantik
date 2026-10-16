#!/usr/bin/env bash
# Run on a dedicated staging/production host with a protected .env and preconfigured registry login.
set -euo pipefail
: "${ATLANTIK_IMAGE:?Set ATLANTIK_IMAGE to an immutable image tag or digest}"
: "${APP_ENV:?Set APP_ENV to staging or production}"
case "$APP_ENV" in staging|production) ;; *) echo 'Invalid deployment environment' >&2; exit 1;; esac
if [[ ! "$ATLANTIK_IMAGE" =~ @sha256:[0-9a-f]{64}$ && ! "$ATLANTIK_IMAGE" =~ :[0-9a-f]{40}$ ]]; then
 echo 'Use an immutable image digest or full commit SHA tag' >&2
 exit 1
fi
export ATLANTIK_IMAGE APP_ENV
# Schema migrations are additive. Roll back application images only; never automatically reverse a migration.
docker compose -f compose.yaml -f compose.release.yaml pull api worker scheduler migrate
docker compose -f compose.yaml -f compose.release.yaml up -d --no-build --wait
curl --fail --silent --show-error "http://127.0.0.1:${HTTP_PORT:-8080}/health/ready"
