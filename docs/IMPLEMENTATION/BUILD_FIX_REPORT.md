# Build Fix Report

## Root cause

The API compilation failures were all TypeScript contract mismatches: an HTTP header can contain multiple values, a nullable Prisma field was supplied to an optional parameter, a JSON union type was spread as though it were always an object, and an outbox call omitted its transaction argument.

## Files changed

- `apps/api/src/identity/authorization/route-organization-context.guard.ts`
- `apps/api/src/identity/verification-engine/verification-engine.service.ts`
- `apps/api/src/organization/role.service.ts`

## Errors resolved

1. The organization context guard now reads `x-organization-id` from the raw request headers and handles `undefined`, one `string`, and a single-element `string[]`. Empty or multi-value arrays are rejected as ambiguous.
2. The verification resend audit call converts a nullable `userId` to `undefined` when absent, matching the audit method contract.
3. `outboxPayload()` is declared as `Prisma.InputJsonObject`, which preserves its existing object-only runtime value and makes its later spread operation type-safe.
4. The permission-grant outbox call now passes the active Prisma transaction required by the repository signature.

## Verification performed

Both requested commands were attempted:

- `pnpm typecheck` — **BLOCKED before TypeScript compilation**. pnpm attempted dependency restoration and failed DNS resolution for `registry.npmjs.org` (`ERR_PNPM_META_FETCH_FAIL` / `ENOTFOUND`). No TypeScript compiler result was produced.
- `pnpm build` — **BLOCKED before the build** for the same dependency-restoration and DNS failure. No build result was produced.

Once registry access and the local dependency store are available, run:

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm build
```

The fixes are intentionally limited to the four reported compile errors. Build and typecheck success remain unverified.
