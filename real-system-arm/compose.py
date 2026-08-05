import sys, json, time

claims = json.load(open(sys.argv[1]))

def local_checks(c):
    now = int(time.time())
    return {
        "P": True,                                   # policy present/applicable (constructed below)
        "E": bool(c.get("iss","").startswith("https://token.actions.githubusercontent.com")
                  and c.get("iat",0) <= now < c.get("exp", now+1)),  # issuer + freshness
        "S": True,                                   # runner state accepted
        "A": bool(c.get("sub")),                     # authority: an authenticated subject exists
        "M": True,                                   # no measurement gate here
    }

def binding(required, c):
    # B: every required subject coordinate must match the token's actual claim
    for k, v in required.items():
        if str(c.get(k)) != str(v):
            return False, f"binding.{k}"
    return True, None

def transaction(name, required, c):
    loc = local_checks(c)
    ok_b, gate = binding(required, c)
    verdict = "ALLOW" if (all(loc.values()) and ok_b) else "DENY"
    first_gate = gate if not ok_b else ("verified" if verdict=="ALLOW" else "component")
    return {"case": name, "required": required, "local_verdicts": loc,
            "binding_pass": ok_b, "first_rejecting_gate": first_gate, "verdict": verdict}

# matched pair on the SAME real token: policy-match (ref matches) vs policy-mismatch (env=production)
required_match = {"repository": claims.get("repository"), "ref": claims.get("ref")}
required_env   = {"repository": claims.get("repository"), "environment": "production"}

out = {
  "real_evidence_source": "GitHub Actions OIDC token (token.actions.githubusercontent.com)",
  "token_claims": claims,
  "transactions": [
    transaction("policy-match (ref+repo)", required_match, claims),
    transaction("policy-requires-environment=production", required_env, claims),
  ],
}
print(json.dumps(out, indent=2))
