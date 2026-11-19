# TunnelSniff team work split

Use these labels for the four team members: **You**, **tm2**, **tm3**, and **tm4**. Each member should make and explain their own contribution. Coordinate interfaces before merging, review one another's work, and keep at least five meaningful commits across the team.

| Member | Main responsibility | Concrete deliverables |
|---|---|---|
| **You (team lead/integrator)** | CLI, authorization flow, scope handling, integration | `tunnelsniff.py`; validate module interfaces; coordinate review and release checklist; write final report sections on tool overview and lifecycle mapping. |
| **tm2** | PCAP parsing and metadata extraction | `tunnelsniff/parser.py`; handle DNS, HTTP, TLS-visible metadata and mDNS; document parser limitations and capture privacy. |
| **tm3** | Shared scoring and DNS/mDNS detection | `tunnelsniff/scoring.py`, `rules_dns.py`, `rules_mdns.py`; explain thresholds and false-positive cases. |
| **tm4** | HTTP/TLS detection, reports, documentation | `rules_http.py`, `report.py`; maintain README/RoE and report layout; prepare a synthetic demo capture and screenshots if time allows. |

## Shared work expected from everyone

- Review the full tool and learn to explain the code in an oral interview.
- Do not use captures from third-party or shared networks without written authorization.
- Keep generated reports and real captures out of Git. Use synthetic or instructor-provided samples only.
- Each person should commit their own changes with descriptive messages. Suggested sequence: project structure; parser; scoring; DNS/mDNS rules; HTTP/TLS rules; CLI and scope; reports and README; final documentation.
- The team lead checks the public repository, five or more meaningful commits, `v1.0.0` release, report PDF (3–5 pages with the completed assessment coversheet), and VLE submission.

## Suggested report ownership

You: tool description and lifecycle mapping. tm2: parser design and challenges. tm3: scoring, ethical safeguards, and threshold tuning. tm4: HTTP/TLS and mDNS limitations, future improvements, references, and final formatting. All members review the final report before submission.
