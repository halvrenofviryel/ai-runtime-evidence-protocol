# Execution environment

Recorded for the run `VAARA-SEP2828-REPRODUCTION-20260913T132310Z-96321b403812`. Local filesystem paths are deliberately omitted.

| Item | Value |
| --- | --- |
| Python | 3.12.3 (`/usr/bin/python3.12`) |
| Python interpreter SHA-256 | e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f |
| Platform (as recorded by the runner) | Linux-6.11.0-29-generic-x86_64-with-glibc2.39 |
| Kernel | Linux 6.11.0-29-generic |
| OS | Ubuntu 24.04.4 LTS |
| Architecture | x86_64 |
| Locale | LANG=en_US.UTF-8, LC_ALL=unset |
| Third-party Python packages installed for this run | none |
| `PYTHONPATH` / `PYTHONHOME` / `VIRTUAL_ENV` | unset |

## Dependency boundary, verified on the pinned source before execution

`conformance/sep2828/run.py`, `record_conformance_v0/_check_independent.py` and
`record_set_v0/_check_independent.py` import only the Python standard library
(`argparse`, `hashlib`, `json`, `re`, `subprocess`, `sys`, `pathlib`, `typing`,
`__future__`). None imports Vaara. The pinned corpus references no third-party
package. Nothing was installed: no Vaara package, no `rfc8785`, no `cryptography`.

`scripts/conformance_runner.py`, the aggregate runner used for the recorded run, likewise
imports only the standard library and invokes each suite's checker in a subprocess.

## Source state

| | |
| --- | --- |
| Repository | https://github.com/vaaraio/vaara |
| Commit (detached checkout) | `d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317` |
| `git status --porcelain` before and after | empty |
| `git diff` / `git diff --cached` before | empty |
| `conformance/sep2828/run.py` Git blob | `679742ba01aace46f902798e5f778507892155ab` |
| `conformance/sep2828/VERSION` | `1.0.0` |
| Corpus source files hashed before and after | 35 files, identical |
| Python bytecode by-products created | none |

No Vaara source file was modified at any point.
