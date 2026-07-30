-- Relational RE-COMPOSITION of the five-layer conjunction, the cross-layer
-- binding stage and the first-gate ladder (corpus v3).
--
-- HONEST LABELLING, unchanged in substance from v2: the inputs are the
-- per-layer typed results and the two subject records ALREADY produced by
-- the Python evaluator. This is a second COMPOSITION code path, NOT
-- independent validation. It verifies no signature, resamples no bootstrap
-- replicate, walks no delegation edge and appraises no attestation object.
--
-- What it does re-derive rather than echo: the typed binding outcome. The
-- binding rules below are a second implementation of
-- composition_rule.bind — the subject strings come from the Python side,
-- but the comparison that turns them into EFFECT_MISMATCH /
-- RESOURCE_MISMATCH / TIME_MISMATCH / PROFILE_MISMATCH / PASS is written
-- again here in SQL. A divergence between the two implementations is
-- therefore detectable (run_sql_oracle.py compares binding_result as well
-- as verdict and gate). That is a transcription check, not independence.
--
-- Branch order mirrors composition_rule exactly:
-- binding rules  — undetermined, effect, resource, time, profile;
-- gate ladder    — policy, evidence, state (contraindicated, stale,
--                  reference — the appraisal order of state_adapter.py),
--                  authority, measurement, binding.
--
-- Set membership uses pipe-delimited strings ('|ledger.read|'), built by
-- run_sql_oracle.py from the canonical_action lists; instr() over those
-- reproduces Python's `x in list` for the atomic identifiers used here.
-- Timestamp comparison is lexicographic on fixed-width UTC Z strings,
-- exactly as in Python; both window boundaries are inclusive.
WITH bound AS (
  SELECT
    id,
    policy_result,
    evidence_result,
    state_result,
    authority_result,
    authority_gate,
    measurement_result,
    CASE
      WHEN canonical_effect IS NULL
        OR canonical_resource IS NULL
        OR canonical_operation IS NULL
        OR canonical_granted_tools IS NULL
        OR canonical_granted_resources IS NULL
        OR canonical_authorised_from IS NULL
        OR canonical_authorised_until IS NULL
        OR canonical_measurement_profile IS NULL
        OR observed_effect IS NULL
        OR observed_resource IS NULL
        OR observed_issued_at IS NULL
        OR observed_measurement_profile IS NULL
      THEN 'UNDETERMINED'
      WHEN observed_effect <> canonical_effect
        OR instr(canonical_granted_tools, '|' || observed_effect || '|') = 0
      THEN 'EFFECT_MISMATCH'
      WHEN observed_resource <> canonical_resource
        OR instr(
             canonical_granted_resources, '|' || observed_resource || '|'
           ) = 0
      THEN 'RESOURCE_MISMATCH'
      WHEN observed_issued_at < canonical_authorised_from
        OR observed_issued_at > canonical_authorised_until
      THEN 'TIME_MISMATCH'
      WHEN observed_measurement_profile <> canonical_measurement_profile
      THEN 'PROFILE_MISMATCH'
      ELSE 'PASS'
    END AS binding_result
  FROM transaction_inputs
),
typed AS (
  SELECT
    id,
    binding_result AS oracle_binding_result,
    CASE
      WHEN policy_result = 'PASS'
       AND evidence_result = 'PASS'
       AND state_result = 'PASS'
       AND authority_result = 'ALLOW'
       AND measurement_result = 'PASS'
       AND binding_result = 'PASS'
      THEN 'ALLOW'
      ELSE 'DENY'
    END AS oracle_verdict,
    CASE
      WHEN policy_result = 'MISSING' THEN 'policy.missing'
      WHEN policy_result = 'STALE' THEN 'policy.stale'
      WHEN policy_result = 'SUBSTITUTED' THEN 'policy.substituted'
      WHEN policy_result = 'INVALID_SIGNATURE' THEN 'policy.signature'
      WHEN evidence_result = 'TAMPERED' THEN 'evidence.integrity'
      WHEN evidence_result = 'REPLAY' THEN 'evidence.replay'
      WHEN state_result = 'CONTRAINDICATED' THEN 'state.contraindicated'
      WHEN state_result = 'STALE' THEN 'state.stale'
      WHEN state_result = 'REFERENCE_MISMATCH' THEN 'state.reference'
      WHEN authority_result <> 'ALLOW' THEN authority_gate
      WHEN measurement_result = 'FAIL_POINT' THEN 'measurement.point'
      WHEN measurement_result = 'FAIL_LCB' THEN 'measurement.confidence'
      WHEN measurement_result = 'PROFILE_MISMATCH' THEN 'measurement.profile'
      WHEN binding_result = 'EFFECT_MISMATCH' THEN 'binding.effect'
      WHEN binding_result = 'RESOURCE_MISMATCH' THEN 'binding.resource'
      WHEN binding_result = 'TIME_MISMATCH' THEN 'binding.time'
      WHEN binding_result = 'PROFILE_MISMATCH'
        THEN 'binding.measurement_profile'
      WHEN binding_result = 'UNDETERMINED' THEN 'binding.undetermined'
      ELSE 'verified'
    END AS oracle_gate
  FROM bound
)
SELECT id, oracle_verdict, oracle_gate, oracle_binding_result
FROM typed
ORDER BY id;
