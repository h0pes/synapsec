# SynApSec Backend

## Stack
Rust, Axum 0.8, SQLx (PostgreSQL), Tower, Tokio, mimalloc

## Architecture
- `src/config/` — Configuration from environment variables
- `src/errors/` — Unified error types using `thiserror`
- `src/models/` — Database models (SQLx `FromRow` structs)
- `src/routes/` — Axum route handlers (thin — delegate to services)
- `src/services/` — Business logic (testable without HTTP)
- `src/parsers/` — Scanner output parsers (implement `Parser` trait)
- `src/middleware/` — Auth, RBAC, request logging

## Patterns
- Route handlers are thin: validate input → call service → return response
- Services contain business logic and are the primary test target
- All database access goes through services, never directly from routes
- Use `AppState` (shared via Axum state) for db pool, redis, config
- Every API response uses `ApiResponse<T>` envelope
- All IDs are UUIDs (v7 for time-ordered entities, v4 for random)
- Timestamps are always UTC `chrono::DateTime<Utc>`, stored as `timestamptz`

## Running
```bash
cargo run         # Start server
cargo test        # Run all tests
cargo clippy      # Lint
```

## Database Migrations
```bash
sqlx migrate add <name>   # Create new migration
sqlx migrate run          # Apply migrations
```

## Microsoft Pragmatic Rust Guidelines

This project follows the [Microsoft Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/).
Below are the applicable guidelines grouped by relevance to this project.

### Universal (apply to all code)

| ID | Rule | How we apply it |
|----|------|-----------------|
| M-UPSTREAM-GUIDELINES | Follow Rust API Guidelines | Standard naming (`as_`/`to_`/`into_`), derive common traits |
| M-STATIC-VERIFICATION | Use static verification | clippy with strict lints, rustfmt, cargo-audit |
| M-LINT-OVERRIDE-EXPECT | Use `#[expect]` not `#[allow]` | Always include `reason` parameter |
| M-PUBLIC-DEBUG | Public types are Debug | All public types derive or impl `Debug`; redact sensitive fields |
| M-PUBLIC-DISPLAY | Public types for reading are Display | Error types, user-facing values |
| M-CONCISE-NAMES | No weasel words | Avoid "Service", "Manager", "Factory" in type names |
| M-REGULAR-FN | Prefer regular over associated functions | Module-level functions unless receiver is clear |
| M-PANIC-IS-STOP | Panic = stop the program | Never use panic for request error handling |
| M-PANIC-ON-BUG | Programming bugs are panics | Contract violations → panic, invalid input → Result |
| M-DOCUMENTED-MAGIC | Document all magic values | Named constants with rationale comments |
| M-LOG-STRUCTURED | Structured logging | Use `tracing` with named fields: `tracing::info!(user_id = %id, "action")` |

### Application-level

| ID | Rule | How we apply it |
|----|------|-----------------|
| M-MIMALLOC-APP | Use mimalloc | `#[global_allocator]` in main.rs |
| M-APP-ERROR | Use anyhow for apps | `anyhow` in main.rs and tests; `thiserror` for library error types |

### Error handling (M-ERRORS-CANONICAL-STRUCTS)

Error types are situation-specific structs, not giant enums:
- Each domain gets its own error type (e.g., `AuthError`, `IngestionError`, `FindingError`)
- All errors implement `Debug`, `Display`, `std::error::Error` via `thiserror`
- Use `is_xxx()` helper methods for pattern matching
- Never expose internal error variants as public API

### Type design

| ID | Rule | How we apply it |
|----|------|-----------------|
| M-DI-HIERARCHY | Types > Generics > dyn Trait | Concrete types first, generics when needed |
| M-STRONG-TYPES | Use proper type families | `Uuid` not `String` for IDs, `PathBuf` for paths |
| M-INIT-BUILDER | Builder for complex types | Types with 4+ optional params use builder pattern |
| M-SERVICES-CLONE | Services are Clone | `AppState` uses `Arc<Inner>` for cheap cloning |
| M-AVOID-WRAPPERS | Hide smart pointers | Public APIs expose `&T`, not `Arc<Mutex<T>>` |

### Safety

| ID | Rule | How we apply it |
|----|------|-----------------|
| M-UNSAFE | Avoid unsafe | No unsafe code expected; if needed, document reason + pass Miri |
| M-UNSOUND | All code must be sound | Non-negotiable |

### Performance

| ID | Rule | How we apply it |
|----|------|-----------------|
| M-HOTPATH | Profile hot paths early | Use `criterion` for parser and deduplication benchmarks |
| M-YIELD-POINTS | Yield in long async tasks | CPU-bound parsing yields every 10-100μs |
| M-THROUGHPUT | Optimize for throughput | Batch operations, exploit CPU caches |

### Documentation

| ID | Rule | How we apply it |
|----|------|-----------------|
| M-FIRST-DOC-SENTENCE | First sentence ≤15 words | Concise summary line for all public items |
| M-MODULE-DOCS | Module documentation | Every public module has `//!` docs |
| M-CANONICAL-DOCS | Standard doc sections | Summary, Examples, Errors, Panics as applicable |
