# Vendored reference implementations

These four files are **unmodified** copies of the reference Python shipped with
the AIOS v8 closure-pass specification:

| File | From |
|---|---|
| `event_log.py` | v8 / AIOS_Runtime_Protocol.md §§1, 3, 4, 5 normative substrate |
| `test_event_log.py` | v8 / 12 tests (incl. genuine seq-gap adversarial test) |
| `conservation_scan.py` | v5 / Verification Spec §1 reference |
| `test_conservation_scan.py` | v5 / 8 breach-detection tests |

They are kept here verbatim so reviewers can diff the package version in
`src/aios/` against the ground-truth spec reference.

## Running

```
python examples/reference/test_conservation_scan.py
python examples/reference/test_event_log.py
```

## Known Windows quirk

`event_log.py::EventLog._open_new_segment` opens the segment file twice
(once as `"wb"` for header write + fsync, then as `"r+b"` for append). The
first handle is not explicitly closed; POSIX tolerates this but Windows holds
the file lock until garbage collection, which races the `tempfile.TemporaryDirectory`
cleanup in some of the event-log tests and produces `PermissionError [WinError 32]`
**after** the assertions have already passed.

The package version in `src/aios/runtime/event_log.py` fixes this; frame hash
output is unchanged (the fix is a handle close, not a content change).
