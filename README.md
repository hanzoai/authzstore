# authzstore

Hanzo's xorm-backed adapter for [hanzoai/authz](https://github.com/hanzoai/authz)
policies. Implements both `persist.Adapter` and `persist.FilteredAdapter` on top
of a caller-provided `*xorm.Engine`.

Replaces `hanzoai/xorm-adapter/v3` (which was a brand-renamed fork of
`casdoor/xorm-adapter`) with a focused 270-line package that:

- operates directly against the canonical `(ptype, v0, v1, v2, v3, v4, v5)` row
  shape — wire-compatible with any existing `authz_*_rule` / `casbin_*_rule`
  tables;
- runs `SavePolicy` inside a single `engine.Transaction` (DELETE + batched
  INSERT) — no deny-all window on crash;
- picks the INSERT batch size at runtime via `pragma_compile_options` for
  SQLite (respecting `SQLITE_MAX_VARIABLE_NUMBER`) and uses 8000-row batches
  on Postgres / MySQL;
- validates the table name against `^[a-zA-Z_][a-zA-Z0-9_]*$` at construction
  so callers cannot smuggle DDL through the string-concatenated WHERE / DELETE
  fragments.

## Install

```bash
go get github.com/hanzoai/authzstore
```

## Use

```go
import (
    authzengine "github.com/hanzoai/authz"
    "github.com/hanzoai/authzstore"
    "github.com/hanzoai/xorm"
)

eng, err := xorm.NewEngine("sqlite", "iam.db")
if err != nil { return err }

adapter, err := authzstore.New(eng, "authz_api_rule", "")
if err != nil { return err }

e, err := authzengine.NewEnforcer("model.conf", adapter)
```

The struct tags on `AuthzRule` match the historical `xorm-adapter` DDL byte-
for-byte, so `Sync2` against a pre-existing populated table is a no-op.

## Tests

```bash
go test -count=1 -race .
```

Includes a concurrent reader/writer test that proves `SavePolicy` never
exposes a deny-all window mid-rewrite.

## License

Apache-2.0.
