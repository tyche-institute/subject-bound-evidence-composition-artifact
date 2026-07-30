# Lab A0: Protocol-valid, Unauthorized

Статус: synthetic core + hybrid A2A adapter + typed path suite (dead gates closed)  
Дата: 2026-07-27 (v4; предыдущая версия 2026-07-25)

## Research question

Может ли verifier отличить полностью schema-valid A2A-like transaction,
отдельно валидный authorization artefact и отдельно валидный effect receipt,
если их семантика несовместима?

Это не A2A conformance suite. A2A wire envelope и boundary-seal regression
уже проверяются существующим `a2a-boundary-seal/`. Здесь изолируется
дополнительная experimental semantics:

```text
native authorization A0
    × native evidence E0
    × composed seam C1
```

## Corpus

`corpus.json` содержит один frozen base object и 20 deterministic patches:

- 4 положительных;
- 16 protocol-valid отрицательных;
- 15 отрицательных специально сохраняют `A0=VALID` и `E0=VALID`;
- один проверяет unbound subdelegation;
- один проверяет good runtime state при отсутствующем mandate.

Mutation families:

- operation/resource/tool/effect substitution;
- tenant/audience drift;
- forbidden subdelegation;
- expiry/revocation between proof and effect;
- one-time replay;
- amount/currency mismatch;
- canonicalization-profile mismatch;
- changed request after authorization commitment;
- receipt/action mismatch;
- favourable state without authority.

## Run

```bash
python verify_corpus.py
python adapters/boundary_seal_adapter.py
python verify_delegation_paths.py
python run_sql_oracle.py
```

Результаты записываются в четыре отдельные директории:

- `results/` — исходный 20-vector semantic corpus;
- `results-boundary-adapter/` — 7 cases поверх записанного A2A evidence;
- `results-delegation-paths/` — 16 typed paths длины 1/2/4;
- `results-sql-oracle/` — relational oracle по тем же expanded inputs.

## v4 change (2026-07-27): dead gates closed, honest field names

Реализованы пункты review E5 / C-14 / dead-gate finding
(`full-independent-review-preprint-03-2026-07-27.md`,
`r2-minimum-experiment-plan-2026-07-27.md`): четыре gate —
`protocol.valid`, `edge.signature`, `effect.native_validity`,
`effect.time_binding` — были мёртвыми ветками ОДНОВРЕМЕННО в Python
evaluator и в relational oracle. В `delegation-paths.json` добавлены
четыре case, каждый изолирует один gate; ветки теперь срабатывают в
обеих реализациях с одинаковой локализацией:

| case | gate | stage_id | stage_index |
| --- | --- | --- | ---: |
| `D1_protocol_invalid` | `protocol.valid` | `edge-0` (по конвенции) | 0 |
| `D2_signature_invalid_second_edge` | `edge.signature` | `edge-1` | 1 |
| `D1_receipt_native_invalid` | `effect.native_validity` | `effect` | 2 |
| `D1_receipt_effect_time_outside_window` | `effect.time_binding` | `effect` | 2 |

Определение `delegation_edge_matches` уточнено: считаются case,
отклонённые именно edge-gate (`edge.*`), а не любые stage id с префиксом
`edge-`. Причина: `protocol.valid` — case-level gate, его stage id
`edge-0` назначается по конвенции и не является edge-локализацией; по
старому определению он бы засчитался (9/9 вместо честных 8/8).

Переименования полей ради честности (review C-14):

- `results-delegation-paths/summary.json`:
  `native_objects_valid` → `native_object_flags_true`,
  `protocol_valid` → `protocol_flags_true` (per-case поля в
  `verdicts.jsonl` переименованы согласованно:
  `protocol_flag_true`, `native_object_flags_true`);
- `results/summary.json`: `negative_localizations` →
  `negative_gate_rejections` (старое имя подразумевало edge-локализацию,
  которой 20-vector suite не выполняет — `first_bad_edge` копирует id
  единственного edge);
- в `summary.json` всех трёх генераторов добавлен ключ `disclaimer`.

**Flag disclaimer** (также внутри JSON summaries):
`issuer_signature_valid`, `native_evidence_valid` и `protocol_valid` —
corpus-supplied experimental flags; эта лаборатория не выполняет никакой
криптографической верификации. Structural appraisal ≠ cryptographic
attestation. Expected labels написаны автором в той же программе;
согласия на designed corpus — это coverage-проверки, не rates. SQL
oracle независимо перевыводит вердикты из raw case objects, но
разделяет с Python entry point расширение corpus и expected labels.

## Expected differential

Для central semantic-loss vectors:

```text
A0 = VALID
E0 = VALID
C1 = DENY(first_rejecting_gate)
```

Native verifier не считается ошибочным. A0 отвечает, что mandate сам по себе
валиден в момент appraisal. E0 отвечает, что receipt сам по себе валиден и
описывает effect. C1 проверяет, относятся ли они к одной разрешённой
транзакции.

## Claim ceiling

Lab не доказывает:

- A2A/MCP wire conformance;
- interoperability предложенных experimental fields;
- legal validity mandate;
- correctness WAVE/JEDI/MachineMandate adapters;
- protection against cryptographic forgery;
- completeness benchmark относительно всех authority failures.

Исходное поле `first_bad_edge` v0 не было настоящей локализацией: оно
копировало ID единственного case edge (поэтому summary-поле
переименовано в `negative_gate_rejections`). Это исправлено отдельным
typed-path suite, где expected object содержит edge ID и index,
evaluator сканирует paths длины 1/2/4, а multi-fault case возвращает
минимальный bad index. SQL rules не вызывают Python evaluator и
совпадают с ним 16/16. Однако независимость expected labels от общей
design process всё ещё не доказана, а флаги
`issuer_signature_valid` / `native_evidence_valid` / `protocol_valid`
поставляются корпусом — криптографии в этой лаборатории нет.

## GO gate

- 20/20 expected A0/E0/C1 verdicts;
- 16/16 negative gate rejections;
- все later gates после DENY имеют `NOT_EVALUATED`;
- corpus hash и verifier hash сохранены;
- existing boundary-seal 3-vector regression остаётся 3/3.

Дополнительные выполненные gates (v4, 2026-07-27):

- hybrid A2A adapter 7/7;
- typed path suite 16/16;
- first-invalid-stage 13/13;
- delegation-edge ID/index 8/8 (по edge-gate определению, см. выше);
- SQL oracle agreement 16/16 (expected и python-implementation);
- все четыре ранее мёртвые ветки срабатывают в обеих реализациях;
- двойной прогон всех entry points → byte-identical результаты.
