# TunnelSniff

TunnelSniff is an original, offline Python tool that scores **possible** tunneling indicators in authorized packet captures. It analyzes DNS, plaintext HTTP, visible TLS metadata, and multicast DNS (mDNS). It is a passive detector: it does not generate traffic, perform exploitation, decrypt TLS, or transmit findings.

**Category:** Network Attack (defensive analysis)  
**Python:** 3.10+  
**License:** MIT

> Use only on captures you created, were given for a lab, or are explicitly authorized to analyze. Unauthorized access or interception may violate Malaysia's Computer Crimes Act 1997. This project is for controlled education and defensive analysis.

## Attack lifecycle mapping

| Lifecycle stage | TunnelSniff's role |
|---|---|
| Command and control / exfiltration | DNS, HTTP(S), and mDNS can be abused as covert channels after a host is compromised. |
| Detection | TunnelSniff inspects an offline capture for suspicious patterns and provides scored indicators for a human analyst to validate. |
| Out of scope | It does not create tunnels, operate a C2 server, decrypt TLS, exploit hosts, or exfiltrate data. |

## Detection approach

- **DNS:** label length and entropy, TXT/NULL query types, and query volume by queried name.
- **HTTP:** visible request URL/header indicators, request timing, and unusually large visible payloads.
- **HTTPS:** packet timing and size, destination IP, and SNI when present in the capture. Encrypted content is not decrypted or inspected.
- **mDNS:** service/instance name entropy, TXT record size, and record volume by source host.

The shared scoring helpers make the rules consistent and explainable. Thresholds are heuristic, not proof of a tunnel. A finding should be reviewed against the environment and the original capture.

## Installation

```text
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

```text
python tunnelsniff.py --help
python tunnelsniff.py --pcap instructor_sample.pcap --scope example.com
python tunnelsniff.py --pcap lab.pcap --scope 192.0.2.10,example.test --channels dns,mdns
python tunnelsniff.py --pcap lab.pcap --scope localhost --threshold 5 --output output
python tunnelsniff.py --pcap lab.pcap --scope localhost --no-save
```

The default scope is `localhost,127.0.0.1,example.com`; only packets matching a declared host/domain or IP are analyzed. Domain matching includes subdomains. mDNS is filtered by source IP, so declare authorized local device IPs to inspect mDNS traffic. `instructor_sample.pcap` above is a placeholder; use an instructor-provided file or create a synthetic lab capture. Use documentation-only addresses/domains for demonstrations. The program displays a legal notice and requires an explicit `yes` before opening the capture. Any other response exits without reading it. `Ctrl+C` stops analysis; live capture is intentionally not implemented.

Reports are printed to the terminal and, unless `--no-save` is used, saved as timestamped JSON under the local `output/` directory. The report contains metadata and findings; do not share captures or reports that could reveal private network details.

## Ethical considerations and data handling

- **Authorization and scope:** the user declares authorized IPs/domains and confirms permission before analysis. Scope filtering is applied to DNS names, HTTP/TLS hosts, and mDNS source IPs.
- **Safe defaults:** the initial scope is limited to localhost, loopback, and `example.com`; there is no live capture mode.
- **Legal notice:** startup refers to Malaysia's Computer Crimes Act 1997 and requires affirmative confirmation.
- **Data minimization:** packet content is not exported; only derived metadata, scores, and rule explanations are written locally. Captures remain where the user placed them.
- **TLS privacy:** no TLS decryption or attempt to bypass encryption. Only visible metadata is considered.
- **Stop mechanism:** `Ctrl+C` interrupts execution. Offline analysis has no capture process to leave running.
- **Responsible disclosure:** if analysis unexpectedly exposes sensitive information, stop, restrict access to the files, notify the authorized engagement lead, and follow the organization's incident and disclosure process. Do not publish or forward the capture.

## Rules of Engagement (RoE)

- **Authorized scope:** only a self-generated lab capture, instructor-provided sample, or capture with written authorization; analyze only the IPs/domains explicitly declared with `--scope`.
- **Time window:** perform work during the lab or engagement window approved by the system/network owner. Offline analysis should use a capture supplied for that window.
- **Permitted techniques:** offline parsing and heuristic analysis of DNS, HTTP, TLS-visible metadata, and mDNS; local report generation.
- **Prohibited actions:** live capture, traffic generation, exploitation, credential collection, TLS decryption, analysis of captures outside the declared scope, and sharing real third-party traffic.
- **Emergency stop:** press `Ctrl+C` or close the terminal. Since the tool is offline-only, no network capture remains active. Secure or delete any unintended sensitive output according to the engagement lead's instructions.

## Limitations

- Rules are heuristic and can flag legitimate CDNs, health checks, software updates, or chatty IoT devices.
- HTTPS content remains encrypted; SNI can be absent or protected, and packet boundaries do not necessarily equal application requests.
- Scapy's packet-level HTTP parsing may miss fragmented or reassembled requests.
- mDNS and DNS can both use DNS packet structures; mDNS is selected by UDP port 5353.
- Scores depend on the capture's completeness and the declared scope. A low score does not establish that a capture is safe.
- Live capture, decryption, alerting, and automated blocking are deliberately excluded.

## Responsible use and references

Use only with permission. For disclosure, report validated findings privately to the system owner through their approved security contact, include minimal reproducible evidence, and allow the owner to coordinate remediation before public discussion.

- Malaysia, Computer Crimes Act 1997 (Act 563).
- IETF RFC 1035, *Domain Names—Implementation and Specification*.
- IETF RFC 6762, *Multicast DNS*.
- Scapy documentation: packet capture reading and protocol layers.

