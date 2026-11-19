# TunnelSniff

<<<<<<< HEAD
TunnelSniff is an original, offline Python tool that scores **possible** tunneling indicators in authorized packet captures. It analyzes DNS, plaintext HTTP, visible TLS metadata, and multicast DNS (mDNS). It is a passive detector: it does not generate traffic, perform exploitation, decrypt TLS, or transmit findings.
=======
TunnelSniff is an offline Python tool that scores **possible** tunneling indicators in authorized packet captures. It analyzes DNS, plaintext HTTP, HTTPS packet metadata, and multicast DNS (mDNS). It is a passive detector: it does not generate traffic, perform exploitation, decrypt TLS, or transmit findings.
>>>>>>> 0a9ce58 (Save current changes)

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
<<<<<<< HEAD
- **HTTP:** visible request URL/header indicators, request timing, and unusually large visible payloads.
- **HTTPS:** packet timing and size, destination IP, and SNI when present in the capture. Encrypted content is not decrypted or inspected.
=======
- **HTTP:** visible request URL/header indicators, timing, and unusually large visible payloads.
- **HTTPS:** packet timing, packet size, destination IP, and SNI when present. Encrypted content is not decrypted or inspected. HTTPS has its own `https` channel in the CLI and report.
>>>>>>> 0a9ce58 (Save current changes)
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
<<<<<<< HEAD
python tunnelsniff.py --pcap instructor_sample.pcap --scope example.com
python tunnelsniff.py --pcap lab.pcap --scope 192.0.2.10,example.test --channels dns,mdns
=======
python tunnelsniff.py --pcap instructor_sample.pcap
python tunnelsniff.py --pcap lab.pcap --scope 192.168.1.0/24,example.test
python tunnelsniff.py --pcap lab.pcap --scope 192.0.2.10 --channels https,mdns
>>>>>>> 0a9ce58 (Save current changes)
python tunnelsniff.py --pcap lab.pcap --scope localhost --threshold 5 --output output
python tunnelsniff.py --pcap lab.pcap --scope localhost --no-save
```

<<<<<<< HEAD
The default scope is `localhost,127.0.0.1,example.com`; only packets matching a declared host/domain or IP are analyzed. Domain matching includes subdomains. mDNS is filtered by source IP, so declare authorized local device IPs to inspect mDNS traffic. `instructor_sample.pcap` above is a placeholder; use an instructor-provided file or create a synthetic lab capture. Use documentation-only addresses/domains for demonstrations. The program displays a legal notice and requires an explicit `yes` before opening the capture. Any other response exits without reading it. `Ctrl+C` stops analysis; live capture is intentionally not implemented.
=======
If `--scope` is omitted, the tool automatically analyzes all observed hosts, domains, IPs, and mDNS names in the selected capture; it does not ask you to enter a scope. It displays the discovered scope in the report and stores it in JSON. The legal notice still requires you to type `yes` to confirm that you are authorized to analyze the entire capture before the file is read. Use `--scope` only when you want to filter the analysis, for example `--scope 192.168.1.0/24,example.test`. CIDR ranges match packet source/destination addresses, while domain scopes include subdomains. Because the parser reads the whole capture before applying an optional filter, the entire file must be authorized for analysis. For mDNS, `--scope` matches source IPs. `instructor_sample.pcap` above is a placeholder; use an instructor-provided file or create a synthetic lab capture. Use documentation-only addresses/domains for demonstrations. `Ctrl+C` stops offline analysis; live capture is not implemented.
>>>>>>> 0a9ce58 (Save current changes)

Reports are printed to the terminal and, unless `--no-save` is used, saved as timestamped JSON under the local `output/` directory. The report contains metadata and findings; do not share captures or reports that could reveal private network details.

## Ethical considerations and data handling

<<<<<<< HEAD
- **Authorization and scope:** the user declares authorized IPs/domains and confirms permission before analysis. Scope filtering is applied to DNS names, HTTP/TLS hosts, and mDNS source IPs.
- **Safe defaults:** the initial scope is limited to localhost, loopback, and `example.com`; there is no live capture mode.
=======
- **Authorization and scope:** by default, scope is discovered from the selected offline capture and all observed records are analyzed after the user confirms authorization for the entire file. An optional `--scope` filter accepts IPs, CIDR ranges, and domains. The parser reads the whole file before applying a filter, so the entire capture must be authorized.
- **Safe defaults:** the tool requires a specific offline file, displays a legal notice, and requires explicit authorization confirmation before reading it. It has no live capture mode or network scanning mode.
>>>>>>> 0a9ce58 (Save current changes)
- **Legal notice:** startup refers to Malaysia's Computer Crimes Act 1997 and requires affirmative confirmation.
- **Data minimization:** packet content is not exported; only derived metadata, scores, and rule explanations are written locally. Captures remain where the user placed them.
- **TLS privacy:** no TLS decryption or attempt to bypass encryption. Only visible metadata is considered.
- **Stop mechanism:** `Ctrl+C` interrupts execution. Offline analysis has no capture process to leave running.
- **Responsible disclosure:** if analysis unexpectedly exposes sensitive information, stop, restrict access to the files, notify the authorized engagement lead, and follow the organization's incident and disclosure process. Do not publish or forward the capture.

## Rules of Engagement (RoE)

- **Authorized scope:** only a self-generated lab capture, instructor-provided sample, or capture with written authorization; analyze only the IPs/domains explicitly declared with `--scope`.
- **Time window:** perform work during the lab or engagement window approved by the system/network owner. Offline analysis should use a capture supplied for that window.
<<<<<<< HEAD
- **Permitted techniques:** offline parsing and heuristic analysis of DNS, HTTP, TLS-visible metadata, and mDNS; local report generation.
=======
- **Permitted techniques:** offline parsing and heuristic analysis of DNS, HTTP, HTTPS-visible metadata, and mDNS; local report generation.
>>>>>>> 0a9ce58 (Save current changes)
- **Prohibited actions:** live capture, traffic generation, exploitation, credential collection, TLS decryption, analysis of captures outside the declared scope, and sharing real third-party traffic.
- **Emergency stop:** press `Ctrl+C` or close the terminal. Since the tool is offline-only, no network capture remains active. Secure or delete any unintended sensitive output according to the engagement lead's instructions.

## Limitations

- Rules are heuristic and can flag legitimate CDNs, health checks, software updates, or chatty IoT devices.
<<<<<<< HEAD
- HTTPS content remains encrypted; SNI can be absent or protected, and packet boundaries do not necessarily equal application requests.
=======
- HTTPS content remains encrypted; SNI can be absent or protected. HTTPS rules use packet timing/volume, not decrypted requests, and packet boundaries do not equal application requests.
>>>>>>> 0a9ce58 (Save current changes)
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

<<<<<<< HEAD
=======
## Team work split

See [TEAM_TASKS.md](TEAM_TASKS.md) for the four-person work split and deliverables.
>>>>>>> 0a9ce58 (Save current changes)
