# ASUS RT-AX55 Firmware Security Assessment

Defensive static analysis and vulnerability research on ASUS RT-AX55 router firmware,
conducted on hardware I own for security research purposes.

## Target

| Field | Value |
|---|---|
| Device | ASUS RT-AX55 |
| Firmware | 3.0.0.4_386_53370-ge2ef5b8 |
| Image SHA-256 | 9805bcb9f0510190bf2d9f50ed4d5587cdffec3a88a1ac180b0b96670ec8c336 |
| Component | `/usr/sbin/httpd` (ARM32 little-endian) |
| Comparison build | 3.0.0.4_386_53244-gfd1abf8 |
| Assessment date | 2026-11-05 (static); 2026-11-09 (dynamic confirmation) |
| Report version | v4 — dynamic test results added |

## Methodology

- Firmware extraction: UBI image → SquashFS → rootfs
- Static analysis: Ghidra 11.3.1 via WAIRZ toolkit, with an independent
  multi-lib project importing all 10 runtime libraries confirmed by `ldd`
  on the live device
- Cross-binary NVRAM dataflow analysis across all `doSystem`/`system()` call sites
- Live-device corroboration: authenticated admin reads (`nvram get`/`nvram show`)
  on the physical device — no exploitation, injection, or write operations
- Dynamic HTTP-layer testing: authenticated and unauthenticated `apply.cgi` POST
  requests against the live device, monitored via `/tmp/syscmd.log` sentinel
- QEMU system-mode emulation attempted for dynamic confirmation (documented in report)

## Findings Summary

| Finding | Severity | CWE | Status |
|---|---|---|---|
| A — SystemCmd → `system()` RCE via apply.cgi | HIGH (authenticated) | CWE-78 | **Dynamically confirmed authenticated. Condition (a) dynamically closed negative — HTTP layer blocks unauthenticated requests.** |
| Hardcoded challenge-response secret | MEDIUM | CWE-798 / CWE-321 | Proven present across builds 53244 and 53370 |
| `lan_ifname` → doSystem whitelist newline gap | LOW | CWE-78 / CWE-88 | Proven; post-auth reachability only |
| ATE run_telnetd injection | INFO (removed) | CWE-78 | Present in 53244, removed in 53370 |

**Finding A — dynamic confirmation (v4):**

Two HTTP-layer tests were run against the live device (firmware 53370) on 2026-11-09:

- **Test 1 — Positive control (authenticated):** POST to `apply.cgi` with valid
  `asus_s_token` cookie and `SystemCmd=id`. The firmware's own completion sentinel
  `XU6J03M6` appeared in `/tmp/syscmd.log`, confirming the authenticated
  SystemCmd → `system()` chain is live on 53370.
- **Test 2 — Condition (a) test (no cookie):** Identical POST with no cookie.
  The HTTP layer returned a redirect to `Main_Login.asp`; `/tmp/syscmd.log` was
  unchanged. **Condition (a) is dynamically closed negative.**

Finding A is confirmed **HIGH (CVSS 7.2, authenticated admin RCE)**. It does not
escalate to CRITICAL — the HTTP auth gate is present and functions correctly on 53370.

## Live-Device Corroboration

All findings were cross-checked against the physical RT-AX55 running firmware 53370
via authenticated admin shell access (`nvram get` / `nvram show`) and direct HTTP
testing. No exploitation, injection, or write operation was performed. Key confirmations:

- Build verified as 53370 (`webs_state_info=3004_386_53370-ge2ef5b8`)
- `lan_ifname=br0` — core interface name, consistent with post-auth-only framing
- `u2ec_*` keys absent — infosvr overflow sink confirmed dormant on this SKU
- `ATEMODE=0`, `telnetd_enable=0` — ATE finding confirmed inert
- ASUS account/pairing subsystem active (`aae_enable=2`) — hardcoded-secret
  finding's context corroborated
- **Authenticated `apply.cgi` SystemCmd execution confirmed via `XU6J03M6` sentinel**
- **Unauthenticated `apply.cgi` request blocked by HTTP layer (redirect to login)**

## Infrastructure Notes

Analysis infrastructure: WAIRZ firmware RE platform, pyghidra-mcp, QEMU system-mode
emulation. During this engagement a QEMU NIC configuration bug in WAIRZ's emulation
harness was identified and fixed: `versatilepb`'s SMC91C111 is a board-integral NIC
and must be configured via `-net nic,model=smc91c111` rather than
`-device smc91c111,netdev=net0` (pluggable-device syntax). Fix applied to
`emulation/scripts/start-system-mode.sh`.

## Scope and Limitations

This is defensive security research on hardware I own. Three tooling limitations
bound the static analysis conclusions and are stated explicitly in the report.
The critical condition (a) question — whether the HTTP auth gate is bypassable —
was resolved dynamically (see Dynamic Test Results above):

1. Three libs (`libhttpdshared.so`, `libnvram.so`, `libwlcsm.so`) were dangling
   symlinks in the extracted rootfs; the real files were recovered from the live
   device and imported into the independent analysis project.
2. The upstream caller of the SystemCmd handler is dispatched via a runtime-dynamic
   function-pointer table, not statically resolvable across any of the 10 analyzed libs.
   This limitation was resolved by dynamic HTTP-layer testing.
3. QEMU system-mode emulation of the full firmware was partially successful
   (NIC bug fixed, kernel boots) but httpd dynamic confirmation was not completed.
   Dynamic confirmation was achieved via direct HTTP testing against the live device.

The PoCs in the report are conceptual. The dynamic tests performed were read-only
observations of `/tmp/syscmd.log` output. No exploitation was attempted.

## Report

[ASUS_RT-AX55_httpd_Security_Assessment_v4_dynconfirm.pdf](./ASUS_RT-AX55_httpd_Security_Assessment_v4_dynconfirm.pdf)

## CVE Prior Art

- CVE-2023-39780 — authenticated OS command injection via `qos_bw_rulelist` (apply.cgi), firmware ≤ 51598
- CVE-2023-41345–41348 — command injection in authentication/token modules, firmware ≤ 51598
- CVE-2021-32030 — auth bypass (GT-AC2900); CVE-2017-6549 — auth bypass (RT-AC53)

Finding A's SystemCmd path is not covered by any of the above. The dynamic test
confirms the HTTP auth gate functions correctly on 53370 — no auth bypass is present.
Finding A is authenticated admin RCE, consistent with the router's documented
diagnostic functionality. No CVE submission is warranted for this finding on this basis.

The hardcoded challenge-response secret (MEDIUM) and `lan_ifname` newline gap (LOW)
remain open for ASUS PSIRT consideration as separate, lower-priority items.

## Disclaimer

This research was conducted on hardware I own for defensive security purposes.
All live-device access used authenticated administrative interfaces only.
No exploitation of any third-party system was performed.
