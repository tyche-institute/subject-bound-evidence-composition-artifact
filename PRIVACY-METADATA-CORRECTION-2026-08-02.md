# Environment-metadata privacy correction

Date: 2026-08-02

Historic hosted-run evidence collected `uname -a` while its `privacy_note`
said that the hostname was not recorded. On GitHub-hosted runners, that
command included an ephemeral runner nodename such as `runnervm...`. The note
was therefore inaccurate for those records.

The collector now records `uname -s -r -m`, which omits the nodename. Historic
records remain unchanged for auditability and must be read with this
correction. The ephemeral runner nodename is not evidence of an identified
physical host, an outside operator, or organizational independence.
