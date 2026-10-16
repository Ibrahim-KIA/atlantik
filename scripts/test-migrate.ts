process.env.DATABASE_URL = process.env.MIGRATION_DATABASE_URL;
await import("../src/migrate.js");
