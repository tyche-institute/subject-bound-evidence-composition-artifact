# External hosted-VM and cross-architecture evidence

Evidence date: 2026-07-28

Repository: `tyche-institute/subject-bound-evidence-composition` (private,
blind-preserving runner repository)

Capsule SHA-256:
`8c8919f9826381da289b73dfd35721938ad5aafea5cd3687b23187589a2d0386`

## Preferred run: Node 24 pinned-action replay

GitHub Actions run:
`https://github.com/tyche-institute/subject-bound-evidence-composition/actions/runs/30347119924`

Source commit:
`c85bc3aa5769a2e94386b2d43e40ef16fafe16ed`

The workflow pins immutable revisions of checkout, setup-python,
upload-artifact, and download-artifact. Every pinned action uses the Node 24
runtime. The run completed without the Node 20 deprecation annotations present
in the earlier successful run.

Results:

- ARM64 job: PASS; reported architecture `aarch64`;
- x86-64 job: PASS; reported architecture `x86_64`;
- capsule verification: 210/210 members on both runners;
- semantic contract: 20/20 on both runners;
- cross-architecture comparison: 11/11;
- exact fixed counts on both runners: 16 policy vectors, 104 composed
  transactions, 8 binding denials, 21 EATF rows, 104 transfer rows, 372
  revocation cases, and 96 fault cases;
- same source capsule, source manifest, release overlay, and exact dependency
  versions on both architectures.

Integrity anchors:

- complete downloaded-evidence manifest:
  `8d2275f3fbbb60f98b3b36f7f514c1abdf48f313a4843d02e207cd510cf82c23`;
- comparison JSON:
  `9e2ac18591a53c8a46fe73151aa7b1e681473b6eb32199380e98073225218b08`;
- ARM64 nested evidence manifest:
  `47cf7f31ee7e8fa4f0e0b294e0826e08738d86ab809e8efa36c051088dbf28c6`;
- x86-64 nested evidence manifest:
  `0e828ea81283a727c20436f89e91d61371f0a3176c4aefbcecbb22f93d3a5eda`.

All rows in both nested evidence manifests and all 25 rows in the complete
downloaded-evidence manifest were independently rechecked after download.

## Earlier successful run

Run:
`https://github.com/tyche-institute/subject-bound-evidence-composition/actions/runs/30346942512`

Source commit:
`428ce24b6d77b4b9691d5e42a94f0f39eacea918`

This run also passed both architecture jobs, both 20/20 semantic contracts,
and the 11/11 comparison. It is retained as repeat evidence. Its pinned action
revisions used Node 20 and GitHub emitted a deprecation annotation while
forcing Node 24. No scientific assertion failed.

Integrity anchors:

- complete downloaded-evidence manifest:
  `7b07c138f25083a46d46687522ad41afe91a596d133a06ac1782a8999a6dc62f`;
- comparison JSON:
  `a0a48c31db1414e962ab3fce266efbb724422c5ebdfbdf9012be950601ace967`;
- ARM64 nested evidence manifest:
  `dc0e28132e7b4e5568fe3075807d3ede01ef5d157052c52b0fe5f89b43cb70c8`;
- x86-64 nested evidence manifest:
  `a1551a807c1bd21d219d77ed4dafe51108521eb0053ee29128641f2cd2f5b157`.

## Claim boundary

These runs establish repeat execution from the same sealed source capsule on
fresh GitHub-hosted VMs reporting two CPU architectures. They do not establish
the physical identity of the underlying machines, hardware-TPM execution,
outside-operator independence, deployed-system validity, or immutable public
availability. Those remain separate gates.
