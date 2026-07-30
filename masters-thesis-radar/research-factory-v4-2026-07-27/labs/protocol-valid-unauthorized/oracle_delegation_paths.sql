WITH edge_with_parent AS (
  SELECT
    e.*,
    c.effect_time,
    c.root_principal,
    c.root_role,
    c.root_operations,
    c.root_resources,
    c.root_tools,
    c.root_audiences,
    c.root_purposes,
    c.root_amount_max,
    c.root_currency,
    p.delegate AS previous_delegate,
    p.to_role AS previous_role,
    p.grant_operations AS previous_operations,
    p.grant_resources AS previous_resources,
    p.grant_tools AS previous_tools,
    p.grant_audiences AS previous_audiences,
    p.grant_purposes AS previous_purposes,
    p.grant_amount_max AS previous_amount_max,
    p.grant_currency AS previous_currency,
    p.grant_delegable AS previous_delegable
  FROM edges e
  JOIN cases c ON c.case_id = e.case_id
  LEFT JOIN edges p
    ON p.case_id = e.case_id AND p.edge_index = e.edge_index - 1
),
violations AS (
  SELECT case_id, 'edge-0' AS stage_id, 0 AS stage_index,
         0 AS priority, 'protocol.valid' AS gate
  FROM cases WHERE protocol_valid = 0

  UNION ALL
  SELECT case_id, edge_id, edge_index, 10, 'edge.lineage'
  FROM edge_with_parent
  WHERE delegator != CASE WHEN edge_index = 0 THEN root_principal ELSE previous_delegate END
     OR from_role != CASE WHEN edge_index = 0 THEN root_role ELSE previous_role END

  UNION ALL
  SELECT case_id, edge_id, edge_index, 20, 'edge.signature'
  FROM edge_with_parent WHERE issuer_signature_valid = 0

  UNION ALL
  SELECT case_id, edge_id, edge_index, 30, 'edge.parent_delegable'
  FROM edge_with_parent
  WHERE edge_index > 0 AND previous_delegable = 0

  UNION ALL
  SELECT e.case_id, e.edge_id, e.edge_index, 40, 'edge.role_transition'
  FROM edge_with_parent e
  WHERE NOT EXISTS (
    SELECT 1 FROM role_transitions r
    WHERE r.from_role = e.from_role AND r.to_role = e.to_role
  )

  UNION ALL
  SELECT case_id, edge_id, edge_index, 50, 'edge.status'
  FROM edge_with_parent WHERE status != 'active'

  UNION ALL
  SELECT case_id, edge_id, edge_index, 60, 'edge.freshness'
  FROM edge_with_parent
  WHERE NOT (not_before <= effect_time AND effect_time <= expires_at)

  UNION ALL
  SELECT case_id, edge_id, edge_index, 70, 'edge.scope.operations'
  FROM edge_with_parent e
  WHERE EXISTS (
    SELECT 1 FROM json_each(e.grant_operations) child
    WHERE NOT EXISTS (
      SELECT 1 FROM json_each(
        CASE WHEN e.edge_index = 0 THEN e.root_operations ELSE e.previous_operations END
      ) parent WHERE parent.value = child.value
    )
  )

  UNION ALL
  SELECT case_id, edge_id, edge_index, 71, 'edge.scope.resources'
  FROM edge_with_parent e
  WHERE EXISTS (
    SELECT 1 FROM json_each(e.grant_resources) child
    WHERE NOT EXISTS (
      SELECT 1 FROM json_each(
        CASE WHEN e.edge_index = 0 THEN e.root_resources ELSE e.previous_resources END
      ) parent WHERE parent.value = child.value
    )
  )

  UNION ALL
  SELECT case_id, edge_id, edge_index, 72, 'edge.scope.tools'
  FROM edge_with_parent e
  WHERE EXISTS (
    SELECT 1 FROM json_each(e.grant_tools) child
    WHERE NOT EXISTS (
      SELECT 1 FROM json_each(
        CASE WHEN e.edge_index = 0 THEN e.root_tools ELSE e.previous_tools END
      ) parent WHERE parent.value = child.value
    )
  )

  UNION ALL
  SELECT case_id, edge_id, edge_index, 73, 'edge.scope.audiences'
  FROM edge_with_parent e
  WHERE EXISTS (
    SELECT 1 FROM json_each(e.grant_audiences) child
    WHERE NOT EXISTS (
      SELECT 1 FROM json_each(
        CASE WHEN e.edge_index = 0 THEN e.root_audiences ELSE e.previous_audiences END
      ) parent WHERE parent.value = child.value
    )
  )

  UNION ALL
  SELECT case_id, edge_id, edge_index, 74, 'edge.scope.purposes'
  FROM edge_with_parent e
  WHERE EXISTS (
    SELECT 1 FROM json_each(e.grant_purposes) child
    WHERE NOT EXISTS (
      SELECT 1 FROM json_each(
        CASE WHEN e.edge_index = 0 THEN e.root_purposes ELSE e.previous_purposes END
      ) parent WHERE parent.value = child.value
    )
  )

  UNION ALL
  SELECT case_id, edge_id, edge_index, 80, 'edge.scope.currency'
  FROM edge_with_parent
  WHERE grant_currency != CASE
    WHEN edge_index = 0 THEN root_currency ELSE previous_currency END

  UNION ALL
  SELECT case_id, edge_id, edge_index, 81, 'edge.scope.amount_max'
  FROM edge_with_parent
  WHERE grant_amount_max > CASE
    WHEN edge_index = 0 THEN root_amount_max ELSE previous_amount_max END

  UNION ALL
  SELECT a.case_id, 'action', c.hops, 10, 'action.subject_role'
  FROM actions a JOIN cases c ON c.case_id = a.case_id
  JOIN edges terminal
    ON terminal.case_id = a.case_id AND terminal.edge_index = c.hops - 1
  WHERE a.subject != terminal.delegate OR a.role != terminal.to_role

  UNION ALL
  SELECT a.case_id, 'action', c.hops, 20, 'action.operation'
  FROM actions a JOIN cases c ON c.case_id = a.case_id
  JOIN edges terminal
    ON terminal.case_id = a.case_id AND terminal.edge_index = c.hops - 1
  WHERE NOT EXISTS (
    SELECT 1 FROM json_each(terminal.grant_operations) allowed
    WHERE allowed.value = a.operation
  )

  UNION ALL
  SELECT a.case_id, 'action', c.hops, 21, 'action.resource'
  FROM actions a JOIN cases c ON c.case_id = a.case_id
  JOIN edges terminal
    ON terminal.case_id = a.case_id AND terminal.edge_index = c.hops - 1
  WHERE NOT EXISTS (
    SELECT 1 FROM json_each(terminal.grant_resources) allowed
    WHERE allowed.value = a.resource
  )

  UNION ALL
  SELECT a.case_id, 'action', c.hops, 22, 'action.tool'
  FROM actions a JOIN cases c ON c.case_id = a.case_id
  JOIN edges terminal
    ON terminal.case_id = a.case_id AND terminal.edge_index = c.hops - 1
  WHERE NOT EXISTS (
    SELECT 1 FROM json_each(terminal.grant_tools) allowed
    WHERE allowed.value = a.tool
  )

  UNION ALL
  SELECT a.case_id, 'action', c.hops, 23, 'action.audience'
  FROM actions a JOIN cases c ON c.case_id = a.case_id
  JOIN edges terminal
    ON terminal.case_id = a.case_id AND terminal.edge_index = c.hops - 1
  WHERE NOT EXISTS (
    SELECT 1 FROM json_each(terminal.grant_audiences) allowed
    WHERE allowed.value = a.audience
  )

  UNION ALL
  SELECT a.case_id, 'action', c.hops, 24, 'action.purpose'
  FROM actions a JOIN cases c ON c.case_id = a.case_id
  JOIN edges terminal
    ON terminal.case_id = a.case_id AND terminal.edge_index = c.hops - 1
  WHERE NOT EXISTS (
    SELECT 1 FROM json_each(terminal.grant_purposes) allowed
    WHERE allowed.value = a.purpose
  )

  UNION ALL
  SELECT a.case_id, 'action', c.hops, 30, 'action.amount_currency'
  FROM actions a JOIN cases c ON c.case_id = a.case_id
  JOIN edges terminal
    ON terminal.case_id = a.case_id AND terminal.edge_index = c.hops - 1
  WHERE a.currency != terminal.grant_currency
     OR a.amount > terminal.grant_amount_max

  UNION ALL
  SELECT r.case_id, 'effect', c.hops + 1, 10, 'effect.native_validity'
  FROM receipts r JOIN cases c ON c.case_id = r.case_id
  WHERE r.native_evidence_valid = 0

  UNION ALL
  SELECT r.case_id, 'effect', c.hops + 1, 20, 'effect.time_binding'
  FROM receipts r JOIN cases c ON c.case_id = r.case_id
  WHERE r.effect_time != c.effect_time

  UNION ALL
  SELECT r.case_id, 'effect', c.hops + 1, 30, 'effect.action_binding'
  FROM receipts r JOIN cases c ON c.case_id = r.case_id
  JOIN actions a ON a.case_id = r.case_id
  WHERE r.action_json != a.action_json
),
ranked AS (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY case_id ORDER BY stage_index, priority, gate
  ) AS violation_rank
  FROM violations
)
SELECT
  c.case_id,
  CASE WHEN r.gate IS NULL THEN 'ALLOW' ELSE 'DENY' END AS verdict,
  COALESCE(r.gate, 'verified') AS gate,
  r.stage_id,
  r.stage_index
FROM cases c
LEFT JOIN ranked r ON r.case_id = c.case_id AND r.violation_rank = 1
ORDER BY c.ordinal;
