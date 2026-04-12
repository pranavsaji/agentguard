@AGENTS.md

# AgentGuard Web Dashboard

Next.js 16.2 + React 19 App Router. See root `CLAUDE.md` for full project context.

## Dev

```bash
npm install && npm run dev   # http://localhost:3000
```

## Structure

```
src/app/
  dashboard/
    inventory/   # NHI catalog table + detail views
    risk/        # Risk score cards
    policy/      # Policy management (planned)
    jit/         # JIT access requests (planned)
  layout.tsx
  page.tsx
src/components/ui/   # shadcn/ui primitives
src/lib/
  api-client.ts      # Typed fetch client (Bearer token via Clerk)
  utils.ts
```

## Key Conventions

- Auth via Clerk — use `@clerk/nextjs` hooks for session/token access
- API calls go through `src/lib/api-client.ts`, not raw fetch
- UI components use shadcn/ui; add new ones with `npx shadcn@latest add <component>`
- This is Next.js 16 — APIs and conventions may differ from training data. Check `node_modules/next/dist/docs/` before writing routing or data-fetching code
