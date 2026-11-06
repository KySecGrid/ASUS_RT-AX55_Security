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
| Assessment date | 2026-11-05 |

## Methodology

- Firmware extraction: UBI image → SquashFS → rootfs
- Static analysis: Ghidra 11.3.1 via WAIRZ toolkit, with an independent
  multi-lib project importing all 10 runtime libraries confirmed by `ldd`
  on the live device
- Cross-binary NVRAM dataflow analysis across all `doSystem`/`system()` call sites
- Live-device corroboration: authenticated admin reads (`nvram get`/`nvram show`)
  on the physical device — no exploitation, injection, or write operations
- QEMU system-mode emulation attempted for dynamic confirmation (documented in report)

## Findings Summary

| Finding | Severity | CWE | Status |
|---|---|---|---|
| A — SystemCmd → `system()` RCE via apply.cgi | HIGH (handler ungated) | CWE-78 | Handler confirmed ungated; HTTP-layer bypass unverified |
| Hardcoded challenge-response secret | MEDIUM | CWE-798 / CWE-321 | Proven present across builds 53244 and 53370 |
| `lan_ifname` → doSystem whitelist newline gap | LOW | CWE-78 / CWE-88 | Proven; post-auth reachability only |
| ATE run_telnetd injection | INFO (removed) | CWE-78 | Present in 53244, removed in 53370 |

**Finding A — condition (a) result:** Static analysis with all 10 runtime libs loaded
confirms the C handler (`FUN_00052560`) contains no internal authentication check.
The upstream dispatch is runtime-dynamic and not statically resolvable. The auth gate,
if present, operates at the HTTP framework layer (asus_token cookie check before CGI
dispatch). HTTP-layer bypass is the remaining unverified escalation path to CRITICAL.

**One false positive retracted:** A co-located stack write in the sink function was
initially read as a CWE-120 overflow. Disassembly confirms a correctly-sized 256-byte
buffer (`sub sp,#0x140`; write at `sp+0x40` capped at `0x100`; saved `lr` at
`sp+0x14c`, unreachable). Retracted with frame-arithmetic evidence.

## Live-Device Corroboration

All findings were cross-checked against the physical RT-AX55 running firmware 53370
via authenticated admin shell access (`nvram get` / `nvram show`). No exploitation,
injection, or write operation was performed. Key confirmations:

- Build verified as 53370 (`webs_state_info=3004_386_53370-ge2ef5b8`)
- `lan_ifname=br0` — core interface name, consistent with post-auth-only framing
- `u2ec_*` keys absent — infosvr overflow sink confirmed dormant on this SKU
- `ATEMODE=0`, `telnetd_enable=0` — ATE finding confirmed inert
- ASUS account/pairing subsystem active (`aae_enable=2`) — hardcoded-secret
  finding's context corroborated

## Infrastructure Notes

Analysis infrastructure: WAIRZ firmware RE platform, pyghidra-mcp, QEMU system-mode
emulation. During this engagement a QEMU NIC configuration bug in WAIRZ's emulation
harness was identified and fixed: `versatilepb`'s SMC91C111 is a board-integral NIC
and must be configured via `-net nic,model=smc91c111` rather than
`-device smc91c111,netdev=net0` (pluggable-device syntax). Fix applied to
`emulation/scripts/start-system-mode.sh`.

## Scope and Limitations

This is defensive security research on hardware I own. Three tooling limitations
bound the conclusions and are stated explicitly in the report:

1. Three libs (`libhttpdshared.so`, `libnvram.so`, `libwlcsm.so`) were dangling
   symlinks in the extracted rootfs; the real files were recovered from the live
   device and imported into the independent analysis project.
2. The upstream caller of the SystemCmd handler is dispatched via a runtime-dynamic
   function-pointer table, not statically resolvable across any of the 10 analyzed libs.
3. QEMU system-mode emulation of the full firmware was partially successful
   (NIC bug fixed, kernel boots) but httpd dynamic confirmation was not completed.

The PoCs in the report are conceptual and have not been dynamically executed.
No exploitation was attempted against the live device.

## Report

[ASUS_RT-AX55_httpd_Security_Assessment_v3_condA-closed.pdf](./ASUS_RT-AX55_httpd_Security_Assessment_v3_condA-closed.pdf)

## CVE Prior Art

- CVE-2023-39780 — authenticated OS command injection via `qos_bw_rulelist` (apply.cgi), firmware ≤ 51598
- CVE-2023-41345–41348 — command injection in authentication/token modules, firmware ≤ 51598
- CVE-2021-32030 — auth bypass (GT-AC2900); CVE-2017-6549 — auth bypass (RT-AC53)

Finding A's SystemCmd path is not covered by any of the above. Its novelty rests on
whether the HTTP-layer gate is bypassable on current firmware 53370.

## Disclaimer

This research was conducted on hardware I own for defensive security purposes.
All live-device access used authenticated administrative interfaces only.
No exploitation of any third-party system was performed.
