# TPM companion for the frozen 104-case corpus

Status: **prepared and locally preflighted; execution evidence is classified by
the adjacent host-provenance record as hardware TPM, firmware TPM, or vTPM**.

This release tool is deliberately outside the frozen r5 evidence bundle.  It
can produce a TPM companion run without changing a PCR, creating a persistent
handle, touching NV storage, clearing a hierarchy, or copying TPM
private/context state into the evidence output. The runner itself does not
infer the TPM class or physical-machine identity.

## Safety model

The TPM path is quote-only:

1. read public fixed/variable TPM properties;
2. create one **transient** primary under the selected endorsement or owner
   hierarchy;
3. create and load one **transient** signing key below it;
4. quote the selected PCR at its current value 104 times, once for each frozen
   transaction and a unique verifier challenge;
5. verify every quote offline with `tpm2_checkquote`;
6. run 64 predeclared offline mutations against the saved public evidence;
7. explicitly attempt to flush only the two context files created by this run;
8. compare read-only transient and persistent handle censuses before and after;
9. delete the private temporary working directory.

The tool has no invocation path for TPM clear, PCR reset/extend, eviction,
persistent handles, hierarchy changes, dictionary-attack changes, or NV
commands.  `--preflight` parses the source AST, permits only a small command
allowlist, rejects forbidden executable families and unsafe flush arguments,
validates the frozen inputs and mutation plan, and executes **no TPM command**.

The transient primary is not a manufacturer-certified EK and no EK certificate
is claimed. The `createak` profile uses the TPM tool's AK template. The
`create-load` compatibility profile instead creates an ordinary restricted
transient signing key; its encrypted private blob remains inside the private
temporary directory and is deleted after the run. Only the primary public
area/name, signing-key public area/name, TPM public properties, and quote
evidence enter the output.

## Frozen inputs

- corpus SHA-256:
  `1ba6d40d07e62a862b98ec52ab5c189eb491f19e4e1e69a411fba73bbb9a43a8`;
- source capsule SHA-256:
  `8c8919f9826381da289b73dfd35721938ad5aafea5cd3687b23187589a2d0386`;
- exactly 104 unique transaction identifiers.

The qualifying-data profile is:

```text
subject-bound.hardware-quote.v1
|corpus=<frozen-corpus-sha256>
|capsule=<source-capsule-sha256>
|transaction=<transaction-id>
|challenge=<32-byte-random-lowercase-hex>
|pcr=<bank>:<index>
```

`TPMS_ATTEST.extraData` receives the raw 32-byte SHA-256 digest of this UTF-8
transcript.  The transcript therefore binds the corpus, capsule, transaction,
fresh challenge and selected PCR coordinate, while the quote binds the current
PCR value.

## Local preflight

This works on a host with no TPM device:

```sh
./run.sh --preflight
(cd preflight && sha256sum -c SHA256SUMS)
```

Preflight must report `hardware_commands_executed: false`.

## Authorized TPM execution

Use a kernel resource-manager TCTI where possible.  The output path must not
already exist.

```sh
./run.sh \
  --execute-hardware \
  --tcti device:/dev/tpmrm0 \
  --pcr-bank sha256 \
  --pcr-index 16 \
  --primary-hierarchy endorsement \
  --primary-algorithm rsa \
  --ak-algorithm rsa \
  --ak-creation-profile createak \
  --output /absolute/new/path/hardware-tpm-run
```

Some vTPMs reject `tpm2_createak` below a generic transient endorsement
primary because the tool expects a compatible EK policy. The non-destructive
compatibility profile is:

```sh
./run.sh \
  --execute-hardware \
  --tcti device:/dev/tpmrm0 \
  --pcr-bank sha256 \
  --pcr-index 16 \
  --primary-hierarchy owner \
  --primary-algorithm rsa \
  --ak-algorithm rsa \
  --ak-creation-profile create-load \
  --output /absolute/new/path/vtpm-run
```

The exact TCTI string is not written to the evidence bundle: its kind and
SHA-256 are recorded to avoid leaking remote endpoints.  `TPM2TOOLS_TCTI` is
set only for child processes.

The finished output contains public key provenance, environment and TPM
properties, 104 public quote vectors, 64 mutation verdicts, a run manifest
conforming to `hardware-run-manifest.schema.json`, and `SHA256SUMS`.  Context
files and other private working state never leave the temporary directory.
The TPM tools may already have auto-flushed a context when the explicit flush
is attempted, so the authoritative cleanup check is that no new transient or
persistent handle remains in the post-run census.

## Predeclared mutations

Eight representative transaction indices × eight mutations:

- quote-message bit flip;
- signature bit flip;
- selected-PCR value bit flip inside the PCR blob;
- verifier-challenge replay/substitution;
- transaction substitution;
- corpus-hash substitution;
- capsule-hash substitution;
- qualifying-data representation confusion.

All 64 must be rejected by offline `tpm2_checkquote`.

## Claim ceiling

A successful authorized run establishes 104 transaction-bound TPM 2.0 quotes
under one transient signing key on the adjacent identified execution
environment, plus the stated offline mutation behavior. The adjacent
provenance—not this runner—determines whether that environment exposes a
hardware TPM, firmware TPM, or vTPM. A vTPM result must not be cited as
hardware-rooted live attestation or physical-host replication. No profile
establishes manufacturer-certified platform identity, secure application
measurement, trusted wall-clock time, deployed-system validity, or external
semantic labels.
