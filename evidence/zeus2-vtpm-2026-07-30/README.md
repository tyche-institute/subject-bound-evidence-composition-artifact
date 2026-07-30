# zeus2 identified-VM and Microsoft-vTPM evidence

This directory preserves an execution on the configured `zeus2` SSH target,
identified by hashed host state and the adjacent SSH host-key fingerprints in
`ZEUS2-RUN-OVERLAY.json`. It is a distinct Ubuntu 24.04 x86-64 virtual-machine
OS instance exposing `/dev/tpmrm0` and `/dev/tpm0`. DMI identifies Microsoft
Hyper-V and the TPM manufacturer property decodes to `MSFT`.

## Results

- public four-lane replay: 20/20 semantic checks;
- Policy-State Replay: 16 vectors;
- composed transaction corpus: 104 transactions and 8 binding denials;
- typed transfer: 104 transaction rows and 21 EATF rows;
- durable revocation: 372 cases and 96 fault-recovery cases;
- TPM preflight: 11/11 checks and 17/17 negative safety checks;
- live Microsoft-vTPM companion: 104/104 native quote verifications;
- mutation companion: 64/64 native quote rejections;
- unique transactions, challenges, qualifying-data digests, and quote
  messages: 104 each;
- post-run handle census: no new transient handle and no persistent handle;
- exported private/context state: zero files.

The original `createak` attempt below a generic transient endorsement primary
failed closed with `TPM_RC_POLICY`. The final declared compatibility profile
uses an owner-hierarchy transient primary and `tpm2_create`/`tpm2_load`; the
encrypted private blob exists only in the run-private temporary directory.
The final evidence bundle contains only public areas, public keys, quote
vectors, mutation verdicts, environment properties, audits, and hashes.

## Verification

`vtpm-run-owner-rsa-final/SHA256SUMS` verifies the live run. The run manifest
validates against
`release-tools/hardware-tpm-companion-2026-07-28/hardware-run-manifest.schema.json`.
`four-lane/EVIDENCE-SHA256SUMS` verifies the four-lane result. The relocated
preflight checksum file retains its original zeus2-relative source paths;
`LOCAL-VALIDATION.json` records the byte-for-byte source-overlay comparison
and local schema validation.

## Claim boundary

This evidence closes an identified second **VM/OS execution** and a live
**Microsoft vTPM** quote/mutation lane. It does not identify the underlying
physical machine, prove a discrete or firmware hardware TPM, provide an EK
certificate, establish a hardware root of trust, or turn synthetic benchmark
rates into deployed-system rates.
