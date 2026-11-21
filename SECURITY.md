# Security Policy

## Supported Versions

Only the latest minor release receives active security triage and patches.

| Version | Supported          |
| :------ | :----------------- |
| 0.1.x   | Yes                |
| < 0.1.0 | No                 |

---

## Threat Model & Scope

`dnswatch` is designed as a passive wire-format DNS protocol analyzer, tunneling detector, and controlled sinkhole responder operating on untrusted Layer 2/3/4 network datagrams.

### In Scope
- Denial of service, memory exhaustion, or crashes triggered by malformed wire packets (e.g., circular compression pointer loops, truncated header bounds, invalid label lengths).
- Flaws in RFC 1035 §4.1.4 name decompression or cursor locking that cause parser desynchronization.
- Buffer overruns or bounds check omissions in RFC 6891 EDNS(0) OPT pseudo-record parsing.
- Algorithmic complexity vulnerabilities in Shannon entropy scoring or sliding-window state tracking.
- Flaws in synthetic RFC 1035 response serialization or blocklist lookup logic.
- Flaws in structured JSONL telemetry output serialization.

### Out of Scope
- Attacks requiring existing local root or administrator privileges on the capture host.
- Physical network disruptions or hardware tampering.
- Upstream kernel driver flaws (e.g., Npcap driver crashes on Windows or kernel raw socket bugs).
- Cryptographic attacks against encrypted DNS protocols (DoH/DoT) which are out of protocol scope.

---

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

To report a vulnerability:
1. Open a confidential draft security advisory via GitHub Security Advisories on `netequator/dnswatch`.
2. Alternatively, email security disclosures to `netequator@users.noreply.github.com` with:
   - Affected version and component.
   - Proof of concept (`.pcap` file or raw byte sequence demonstrating the issue).
   - Expected behavior versus observed behavior.
3. You will receive an initial response acknowledging receipt within 48 hours.
4. Security advisories will be credited upon coordinated disclosure and patch release.
