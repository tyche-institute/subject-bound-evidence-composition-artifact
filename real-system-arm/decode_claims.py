import sys, base64, json
seg = sys.argv[1].split(".")[1]
seg += "=" * (-len(seg) % 4)
claims = json.loads(base64.urlsafe_b64decode(seg))
keep = ["iss","aud","sub","repository","repository_owner","ref","ref_type",
        "environment","job_workflow_ref","workflow","event_name","actor","run_id",
        "run_attempt","iat","nbf","exp"]
print(json.dumps({k: claims.get(k) for k in keep if k in claims}, indent=2))
