#!/usr/bin/env bash
set -euo pipefail
mkdir -p .local
if [ ! -f .local/test.env ]; then
node --input-type=module <<'JS'
import {randomBytes} from 'node:crypto';import {writeFileSync} from 'node:fs';
const root=randomBytes(24).toString('hex'),app=randomBytes(24).toString('hex'),worker=randomBytes(24).toString('hex');writeFileSync('.local/test.env',`POSTGRES_PASSWORD=${root}\nPOSTGRES_USER=atlantik_migrator\nPOSTGRES_DB=atlantik_test\nAPP_DB_PASSWORD=${app}\nWORKER_DB_PASSWORD=${worker}\nMIGRATION_DATABASE_URL=postgresql://atlantik_migrator:${root}@127.0.0.1:55432/atlantik_test\nDATABASE_URL=postgresql://atlantik_app:${app}@127.0.0.1:55432/atlantik_test\nWORKER_DATABASE_URL=postgresql://atlantik_worker:${worker}@127.0.0.1:55432/atlantik_test\nREDIS_URL=redis://127.0.0.1:56379\nAPP_ENCRYPTION_KEY=${randomBytes(32).toString('base64')}\nBILLING_WEBHOOK_SECRET=${randomBytes(32).toString('hex')}\nBILLING_MODE=simulation\n`,{mode:0o600});
JS
fi
docker inspect atlantik-test-db >/dev/null 2>&1 || docker run -d --name atlantik-test-db --env-file .local/test.env -p 127.0.0.1:55432:5432 postgres:17-alpine >/dev/null
docker inspect atlantik-test-redis >/dev/null 2>&1 || docker run -d --name atlantik-test-redis -p 127.0.0.1:56379:6379 redis:7-alpine >/dev/null
for attempt in {1..30}; do
 if docker exec atlantik-test-db pg_isready -h 127.0.0.1 -U atlantik_migrator -d atlantik_test >/dev/null; then break; fi
 sleep 1
done
node --env-file=.local/test.env --import tsx scripts/test-migrate.ts
