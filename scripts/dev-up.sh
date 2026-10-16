#!/usr/bin/env bash
set -euo pipefail
if [ ! -f .env ]; then
node --input-type=module <<'JS'
import {randomBytes} from 'node:crypto';import {writeFileSync} from 'node:fs';
const hex=()=>randomBytes(32).toString('hex');writeFileSync('.env',`APP_ENV=development\nPOSTGRES_PASSWORD=${hex()}\nAPP_DB_PASSWORD=${hex()}\nWORKER_DB_PASSWORD=${hex()}\nAPP_ENCRYPTION_KEY=${randomBytes(32).toString('base64')}\nBILLING_WEBHOOK_SECRET=${hex()}\nBILLING_MODE=simulation\n`,{mode:0o600});
JS
fi
if [ -n "${CODEX_PROXY_CERT:-}" ]; then
 docker build --secret id=proxy_ca,src="$CODEX_PROXY_CERT" -t atlantik:local .
else
 docker build -t atlantik:local .
fi
docker compose --profile development up -d --no-build --wait
echo 'Atlantik API: http://localhost:8080; development mail: http://localhost:8025'
