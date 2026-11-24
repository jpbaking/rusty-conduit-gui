# phase-0003 — Frontend unit tests & CI integration

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Add automated unit tests for the frontend's pure TypeScript modules (`validate.ts`, `chain.ts`, `format.ts`) runnable via `npm test` with zero new npm dependencies, and wire `npm test` into CI and Release workflows.
- Done when: `(cd src-tauri/ui && npm run check && npm test && npm run build) && python3 scripts/validate-release-config.py` exits 0 with passing unit tests and updated CI/release workflows.
- Pattern to follow: `src-tauri/ui/src/lib/validate.ts`, `src-tauri/ui/src/lib/chain.ts`, `src-tauri/ui/src/lib/format.ts`, and `.github/workflows/ci.yml:20-43`.

## Context
Currently `src-tauri/ui/package.json` has `check` (`svelte-check`) and `build` (`vite build`), but zero automated unit tests. Node 22+ (CI uses Node 22; local host has Node 26) includes `node:test` and `node:assert/strict` plus native TypeScript type-stripping (`node --experimental-strip-types --test` works on both Node 22.6+ and Node 26; note: avoid TypeScript syntax not supported by strip-types such as `enum` or parameter properties, and use `.ts` relative imports or explicit extensions only as compatible with `svelte-check` / `tsconfig.json` — verify `npm run check` and `npm run build` still pass cleanly!).
Check `src-tauri/ui/tsconfig.json` before writing test imports so `svelte-check` and `node --test` both succeed with zero warnings.
Planner decision (resolving sub-task 1 escalation): Approve option (b) so test files stay strictly type-checked by `svelte-check`. Add `"allowImportingTsExtensions": true` to `src-tauri/ui/tsconfig.json` (compatible with `"noEmit": true`) and add minimal ambient declarations for `node:test` and `node:assert/strict` in `src-tauri/ui/src/lib/node-test.d.ts` (both added to Scope: In). Do not use `// @ts-nocheck`.

## Scope
- In: `src-tauri/ui/package.json`, `src-tauri/ui/tsconfig.json`, `src-tauri/ui/src/lib/node-test.d.ts`, `src-tauri/ui/src/lib/validate.test.ts`, `src-tauri/ui/src/lib/chain.test.ts`, `src-tauri/ui/src/lib/format.test.ts`, `src-tauri/ui/dist/**`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/validate-release-config.py`
- Out: `src-tauri/ui/package-lock.json` (zero new npm dependencies), `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh`, `crates/**`

## Sub-tasks
1. [done] Add `src-tauri/ui/src/lib/validate.test.ts` testing `isPort`, `isIpAddress` (IPv4, IPv6, compressed `::`, embedded IPv4, invalid inputs), `isLoopback`, `filterRuleError` (CIDR v4/v6, invalid prefixes, plain domains, `*.domain` wildcards, mid-wildcards, brackets), `denylistedFlag` (short flags `-F`, `-J`, `-i`, bundled flags `-vF`, `-oProxyCommand=foo`, case-insensitive options, allowed flags like `-C`, `-v`), `redactArgs` (flags, `=value`, `-o Name=value`, positional args), and `sessionErrors` (valid profile, missing name/hops, zero ports, allow+block conflict, MITM TTL < 10, reconnect initial > max, OpenSSH denylist). — done when: `node --test src-tauri/ui/src/lib/validate.test.ts` exits 0.
2. [done] Add `src-tauri/ui/src/lib/chain.test.ts` (testing `moved`, `hopRole`, `hopTitle`, `hopBadge`, `authRefs`, `profileRefs`) and `src-tauri/ui/src/lib/format.test.ts` (testing `statusOf`, `isActive`, `stateReason`, `formatBytes`, `formatUptime`, `logLevel`, `passesLevel`). — done when: `node --test src-tauri/ui/src/lib/chain.test.ts src-tauri/ui/src/lib/format.test.ts` exits 0.
3. [done] Add `"test": "node --experimental-strip-types --test src/lib/*.test.ts"` (or compatible Node 22+ command verified locally) to `src-tauri/ui/package.json`, add `- run: npm test` to the `frontend` job in `.github/workflows/ci.yml`, ensure `.github/workflows/release.yml` / `scripts/validate-release-config.py` remain valid (if `release.yml` runs frontend checks directly, add `npm test` there too; if it calls `ci.yml` via `workflow_call`, verify that), and include the rebuilt `src-tauri/ui/dist/` from `npm run build` in this phase's commit so the tracked bundle reflects phase-0002's `HopEditor.svelte` changes. — done when: all commands in `## Verify` exit 0.

## Verify
```sh
(cd src-tauri/ui && npm run check && npm test && npm run build) && python3 scripts/validate-release-config.py
```

## Escalate when
- `tsconfig.json` / `svelte-check` conflicts with Node's `--experimental-strip-types` import resolution in a way that cannot be solved cleanly without changing production files → stop, set Status: needs-human — reason: <exact error>

## Log
- (append-only, one line per event)
- began phase; probed test-file setup with a throwaway src/lib/probe.test.ts (removed); blocked on svelte-check vs node:test import conflict (Escalate when #1)
- planner unblocked phase-0003: approved option (b) — add allowImportingTsExtensions to tsconfig.json + minimal ambient declarations in src/lib/node-test.d.ts so tests remain type-checked; returned sub-task 1 to [todo]
- resumed: added allowImportingTsExtensions to tsconfig.json and ambient src/lib/node-test.d.ts (approved option b); sub-task 1: added validate.test.ts (33 tests over isPort, isIpAddress, isLoopback, filterRuleError, denylistedFlag, redactArgs, sessionErrors)
- sub-task 2: added chain.test.ts (moved, hopRole, hopTitle, hopBadge, authRefs, profileRefs) and format.test.ts (statusOf, isActive, stateReason, formatBytes, formatUptime, logLevel, passesLevel)
- sub-task 3: added npm `test` script (node --experimental-strip-types --test src/lib/*.test.ts), `- run: npm test` in ci.yml frontend job, "npm test" in FRONTEND_COMMANDS of scripts/validate-release-config.py; release.yml unchanged (its verify job calls ci.yml via workflow_call, so npm test runs before packaging); rebuilt dist/
- sub-task 3 fix: first Verify run failed svelte-check (validate.test.ts 276:5/277:5 "'hop' is possibly 'undefined'" — minimal assert.ok type does not narrow); replaced assert.ok(hop) with an explicit throw guard; Verify then passed

## Evidence
- (append-only: command → observed result)
- `node --experimental-strip-types --test src/lib/probe.test.ts` (Node v26.13.0) → pass 1, fail 0
- `npx svelte-check --tsconfig ./tsconfig.json --fail-on-warnings` with probe → 3 ERRORS (node:test, node:assert/strict not found; TS5097 .ts extension import)
- same with `// @ts-nocheck` line 1 of probe → 0 ERRORS 0 WARNINGS
- `ls node_modules/@types` → estree only (no @types/node)
- `node --test src-tauri/ui/src/lib/validate.test.ts` → tests 33, pass 33, fail 0, exit 0
- `node --test src-tauri/ui/src/lib/chain.test.ts src-tauri/ui/src/lib/format.test.ts` → tests 22, pass 22, fail 0, exit 0
- first `(cd src-tauri/ui && npm run check && npm test && npm run build)` → svelte-check 2 ERRORS (validate.test.ts 276:5, 277:5 'hop' is possibly 'undefined')
- after fix `(cd src-tauri/ui && npm run check && npm test && npm run build) && python3 scripts/validate-release-config.py` → exit 0: svelte-check 162 FILES 0 ERRORS 0 WARNINGS; npm test tests 55, suites 20, pass 55, fail 0; vite build ✓ built in 1.98s (dist/assets/index-CShC_wSH.js); RELEASE_CONFIG_OK
- `grep -n 'uses: ./.github/workflows/ci.yml' .github/workflows/release.yml` → 26 (verify job reuses ci.yml, which now runs npm test)
