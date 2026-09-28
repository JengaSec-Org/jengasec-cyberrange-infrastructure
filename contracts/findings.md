# Contract: what a finding must contain

Owner: Scoring & Evaluation. Audience: Red teams and judges. Submitted through the competition website.

| Field | Required | Notes |
|---|---|---|
| Team and cell | yes | Must be a cell in your scope; out-of-scope findings score zero |
| Time (start and end) | yes | Platform clock, used to match your evidence to the logs |
| Title | yes | One line: what is wrong |
| Technique | yes | What class of issue, with an ATT&CK id where one fits |
| Steps to reproduce | yes | Numbered, enough for a judge to repeat it |
| Evidence | yes | Request or response, screenshot, or telemetry event ids |
| Impact | yes | What an attacker gains: data, access, availability |
| Suggested fix | no | Scores extra where it is sound |

**Rules.** First valid report of the same issue wins; later ones are duplicates. Severity is set by the judges, not the reporter. Attacking the platform itself, or destroying logs and evidence, is not a finding — it is disqualification.
