# Native runtime-attestation gate

This lab replaces a structural state fixture with native offline verification of
a frozen TPM 2.0 quote.  It exercises the application binding

`capsule id + outcome digest + verifier challenge -> qualifying data`

and the PCR-16 fold of the outcome digest.  The verifier calls
`tpm2_checkquote`; it therefore checks the signed `TPMS_ATTEST`, qualifying
data, PCR selection, and supplied PCR values with the frozen RSA attestation
key.

## Scope

The source is Tyche Institute's prior first-party
[`aep-pcr16-vector`](https://github.com/tyche-institute/aep-pcr16-vector),
commit `2d22013987e1e98f8f9132832c9db2b967035945`, under the MIT licence.
It was produced with `swtpm`.  This is native cryptographic appraisal of a
software-TPM vector, **not** a hardware-rooted claim, a live deployment result,
or an independent-host replication.

## Run

```sh
python3 verify_runtime_attestation.py
sha256sum -c SHA256SUMS
```

The run contains one affirming control and six targeted negatives:
substituted outcome, replayed challenge, substituted capsule, altered declared
PCR, tampered quote message, and tampered signature.  `cases.json` contains the
author-written expected gates and is hash-pinned by the runner before parsing.
A passing run requires exact verdict-and-gate agreement on all seven cases:
four cryptographic negatives must produce a non-zero native-verifier return
code, while two inconsistent outcome/PCR declarations must fail the explicit
measurement-binding precheck before the native call.

The qualifying-data preimage is exactly
`tyche.aep.qual.v1|capsule=<hex>|outcome=sha256:<hex>|nonce=<hex>`.  The
application hashes those ASCII bytes to a 64-character lowercase hexadecimal
digest; `tpm2_checkquote -q` receives the hex encoding of those 64 ASCII
characters, matching the frozen source vector.
