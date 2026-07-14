# Worker Build Fix Report

## Root cause

The Worker imported the `Prisma` namespace solely to call `Prisma.sql`, but the installed Prisma client type does not expose that helper. This caused both `Property 'sql' does not exist on type 'typeof Prisma'` errors. The wrapping call form also prevented TypeScript from applying the `$queryRaw<T>` generic correctly.

## Files changed

- `apps/worker/src/outbox/outbox-worker.ts`
- `apps/worker/src/runtime.ts`

## Errors resolved

- Removed the unavailable `Prisma` namespace imports.
- Changed the outbox claim to Prisma's supported `$queryRaw<T>` tagged-template API. The SQL text, bind values, result type (`OutboxRecord[]`), and execution behavior are unchanged.
- Changed the database health probe to the same supported `$queryRaw` tagged-template API. Its `SELECT 1` statement is unchanged.

## Verification performed

- `pnpm --filter @noagent4u/worker typecheck` — **BLOCKED before typechecking**. pnpm attempted to restore missing dependencies and could not resolve `registry.npmjs.org` (`ERR_PNPM_META_FETCH_FAIL` / `ENOTFOUND`). No Worker TypeScript result was produced.
- `pnpm typecheck` — **NOT RUN**, as instructed, because the Worker-only typecheck did not complete successfully.

When dependencies are available, run:

```sh
pnpm install --frozen-lockfile
pnpm --filter @noagent4u/worker typecheck
pnpm typecheck
```

No packages other than `apps/worker` were modified. Verification remains pending.
