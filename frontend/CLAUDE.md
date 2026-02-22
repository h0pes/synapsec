# SynApSec Frontend

## Stack
React 18+, TypeScript (strict), Vite, TailwindCSS v4, shadcn/ui

## Architecture
- `src/api/` — Typed API client functions (one file per domain)
- `src/components/` — Reusable components organized by domain
- `src/components/ui/` — shadcn/ui primitives (do not modify directly)
- `src/hooks/` — Custom React hooks
- `src/pages/` — Page-level components (one per route)
- `src/stores/` — Client-side state (auth, preferences)
- `src/types/` — TypeScript type definitions matching API contracts
- `src/lib/` — Utility functions
- `public/locales/` — i18n translation files (en, it)

## Patterns
- All user-facing strings through `useTranslation()` — never hardcoded
- API calls always through typed functions in `src/api/`
- shadcn/ui for all base components — customize via className, never modify source
- TanStack Table for all data tables (findings, applications)
- TanStack Router for type-safe routing
- Custom fonts and design tokens in tailwind.config.ts
- Light/dark theme via CSS variables + ThemeToggle component

## Running
```bash
npm run dev       # Start dev server
npm test          # Run Vitest
npm run lint      # ESLint
npm run build     # Production build
```
