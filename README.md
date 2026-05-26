# iks

`iks` is a collection of Go packages for working with TPM 2.0 devices and related platform-attestation primitives. It builds on [`go-tpm`](https://github.com/google/go-tpm), [`go-attestation`](https://github.com/google/go-attestation), and [`go-eventlog`](https://github.com/google/go-eventlog), and provides higher-level helpers used by Meta's host-attestation tooling.

## Packages

- [`pkg/tpm`](pkg/tpm) — open and operate on a TPM 2.0 device: NV index management, key creation and loading, signing, quoting/attestation, sealing and wrapping, and policy-digest construction.
- [`pkg/blob`](pkg/blob) — typed serialization format for TPM-wrapped data (software-wrapped vs. TPM-wrapped, session type, algorithm metadata).
- [`pkg/chipid`](pkg/chipid) — extract a CPU/platform chip identifier (e.g. AMD SEV-SNP) from the UEFI TPM event log.
- [`pkg/logging`](pkg/logging) — small `log/slog` handlers, including a syslog handler and a no-op handler for tests.

## Requirements

- Go 1.22 or later.
- A TPM 2.0 device accessible via `/dev/tpmrm0` (or `/dev/tpm0`) on Linux. Most operations require appropriate privileges to open the TPM device.
- `pkg/chipid` reads the UEFI event log from `/sys/kernel/security/tpm0/binary_bios_measurements` and is Linux-only.

## Usage

Each example below is self-contained. See each package's GoDoc for the full API.

### `pkg/tpm`

Open a device, read PCRs, and sign a digest with a freshly created key:

```go
import (
    "crypto/sha256"

    "github.com/facebookincubator/iks/pkg/tpm"
    "github.com/google/go-tpm/tpm2"
)

t, err := tpm.OpenTPM("/dev/tpmrm0")
if err != nil { return err }
defer t.Close()

pcrs, err := t.ReadPCRs(0, 1, 7)
if err != nil { return err }

public, private, _, _, _, err := t.CreateKey(
    tpm.SRKECCHandle, "", tpm.GetECCSigningKeyTemplate(),
)
if err != nil { return err }

handle, err := t.LoadKey(tpm.SRKECCHandle, public, private)
if err != nil { return err }
defer t.UnloadKey(handle)

digest := sha256.Sum256([]byte("hello"))
sig, err := t.Sign(handle, tpm2.TPMAlgECDSA, digest[:])
```

### `pkg/blob`

Self-describing wire format for TPM artifacts — useful when persisting wrapped keys or sealed data alongside the metadata needed to reload them:

```go
import "github.com/facebookincubator/iks/pkg/blob"

encoded := blob.Pack(&blob.Blob{
    Btype:   blob.WrapTypeTPM,
    Stype:   blob.PCRSession,
    Public:  public,
    Private: private,
    PCRs:    []uint{0, 7},
})

decoded, err := blob.Unpack(encoded, blob.WrapTypeTPM)
```

### `pkg/chipid`

On AMD SEV-SNP hosts, returns the 64-byte ChipID parsed from the PCR 1 event:

```go
import "github.com/facebookincubator/iks/pkg/chipid"

res, err := chipid.Get()
```

### `pkg/logging`

Routes `slog` records to local syslog as `<msg> key=val …`. Falls back to a no-op handler (never stderr) if syslog is unavailable:

```go
import (
    "log/slog"

    "github.com/facebookincubator/iks/pkg/logging"
)

slog.SetDefault(slog.New(logging.NewSyslogHandler("iks-example")))
```

### End-to-end: seal a secret, persist it, restore it

Combines `pkg/tpm` and `pkg/blob` to seal data, serialize it for storage or transport, then unseal on the same host:

```go
private, public, err := t.Seal([]byte("api-token"), nil)
if err != nil { return err }

encoded := blob.Pack(&blob.Blob{
    Btype: blob.WrapTypeTPM, Stype: blob.NullSession,
    Public: public, Private: private,
})
// write `encoded` to disk, send over RPC, etc.

decoded, _ := blob.Unpack(encoded, blob.WrapTypeTPM)
secret, err := t.Unseal(decoded.Private, decoded.Public, nil)
```

For PCR-bound sealing, derive a policy digest with `t.PCRPolicy(...)` and pass it to `Seal`; use `tpm.Wrap`/`tpm.Unwrap` for payloads larger than 128 bytes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

`iks` is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
