# Typed delegation paths — 1/2/4-hop result

Дата: 2026-07-25  
Verdict: Python evaluator + independent SQL oracle PASS; external labels pending

## Почему появился этот suite

Независимый аудит v0 обнаружил, что старое поле `first_bad_edge` копировало
единственный `case.edge.edge_id`. Оно не доказывало выбор минимального плохого
ребра. Новый suite отделяет этот вопрос от gate-localization.

## Результат

| Метрика | Результат |
| --- | ---: |
| Cases | 12 |
| Protocol-valid | 12/12 |
| Native signature/evidence flags valid | 12/12 |
| Positive controls | 3/3 |
| Negative cases | 9/9 |
| Full expected tuple matches | 12/12 |
| First-invalid-stage matches | 9/9 |
| Delegation-edge ID/index matches | 7/7 |
| Ordered trace matches | 12/12 |
| Hop lengths | 1, 2, 4 |
| Independent SQL oracle ↔ expected | 12/12 |
| Independent SQL oracle ↔ Python evaluator | 12/12 |

`D4_multi_fault_returns_earliest_edge` содержит три дефекта: amplification на
`edge-1`, revocation на `edge-3` и запрещённую terminal action. Evaluator
возвращает `edge-1`, index `1`, а все более поздние стадии маркирует
`NOT_EVALUATED`.

Два дополнительных случая локализуются уже после valid delegation path:

- out-of-scope action → stage `action`, index `4`;
- native-valid receipt для другой action → stage `effect`, index `5`.

## Артефакты

- `delegation-paths.json` — declarative cases и expected edge ID/index;
- `verify_delegation_paths.py` — path builder и ordered evaluator;
- `results-delegation-paths/verdicts.jsonl` — полный stage trace;
- `results-delegation-paths/summary.json` — агрегаты;
- `results-delegation-paths/SHA256SUMS` — corpus/code/output hashes.
- `oracle_delegation_paths.sql` — независимая relational rule
  implementation;
- `run_sql_oracle.py` и `results-sql-oracle/` — загрузка exact expanded
  inputs, SQL verdicts и differential к Python evaluator.

Оба checksum manifests проходят: 5/5 для path suite и 5/5 для SQL oracle.

## Claim ceiling

Suite поддерживает только следующий узкий claim:

> В synthetic typed 1/2/4-hop paths evaluator воспроизводимо совпал с
> заданными edge ID/index/gate для всех 12 cases и выбрал более ранний defect
> в одном multi-fault case; независимая SQL implementation дала те же 12
> verdict tuples.

Он пока не поддерживает:

- независимость expected labels от общей design process;
- native MachineMandate signatures/appraisal/status;
- OS-enforced role isolation;
- persistent replay или asynchronous revocation race;
- real A2A request-byte → mandate → EATF effect binding;
- generalization за пределы frozen synthetic suite.

Следующий evidence-class jump — внешний/manual double-coded label set,
затем adapter к реально проверенным mandate edges. SQL oracle уже отделён от
imperative Python evaluator, но не от нашей общей формализации semantics.
