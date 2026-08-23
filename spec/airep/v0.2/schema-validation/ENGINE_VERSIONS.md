# Schema-validation harness — exact resolved engine/runtime versions

> Required by VALIDATION_CONTRACT §1 (version pinning): "latest at the time" is not an
> evidence baseline. Measured on the machine that produced the committed results.

| Component | Resolved version | Pin source |
|---|---|---|
| Python | 3.12.3 | system interpreter (recorded) |
| `jsonschema` | 4.25.1 | `requirements.lock` |
| `referencing` | 0.37.0 | `requirements.lock` |
| `attrs` | 23.2.0 | `requirements.lock` |
| `rpds-py` | 0.30.0 | `requirements.lock` |
| `jsonschema-specifications` | 2025.9.1 | `requirements.lock` |
| Node | v20.19.6 | system runtime (recorded) |
| `ajv` | 8.20.0 (exact) | `package.json` + `package-lock.json` |

Ajv configuration (contract-pinned): `Ajv2020`, `allErrors: true`, `validateFormats: false`,
`strict: false`. Python configuration: `Draft202012Validator` + local `referencing` registry,
`format` not asserted. The five accepted schemas are consumed byte-unchanged.
