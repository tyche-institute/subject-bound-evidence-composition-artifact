WITH evaluated AS (
  SELECT
    id,
    policy_result,
    evidence_result,
    CASE
      WHEN policy_result = 'PASS' AND evidence_result = 'PASS' THEN 'ALLOW'
      ELSE 'DENY'
    END AS oracle_verdict,
    CASE
      WHEN policy_result = 'MISSING' THEN 'policy.missing'
      WHEN policy_result = 'STALE' THEN 'policy.stale'
      WHEN policy_result = 'SUBSTITUTED' THEN 'policy.substituted'
      WHEN policy_result = 'INVALID_SIGNATURE' THEN 'policy.signature'
      WHEN evidence_result = 'TAMPERED' THEN 'evidence.integrity'
      WHEN evidence_result = 'REPLAY' THEN 'evidence.replay'
      ELSE 'verified'
    END AS oracle_gate
  FROM replay_inputs
)
SELECT
  id,
  oracle_verdict,
  oracle_gate
FROM evaluated
ORDER BY id;
