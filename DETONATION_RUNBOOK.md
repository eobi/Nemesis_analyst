# Detonation Runbook (Phase 5 behavioral worker)

The canonical, ordered detonation procedure. The worker runs it autonomously in a
disposable isolated VM and logs every step (run.log + checklist.json) so nothing
is skipped. STATIC phases are host-safe; everything here runs ONLY in the VM.

## The FakeNet <-> SSH problem (and the fix)
FakeNet-NG's Diverter captures ALL guest traffic, which tears down our SSH control
channel. Handling:
1. PRIMARY — autonomous in-guest agent: a script pre-placed in the guest runs the
   whole sequence on its own and writes artifacts + a status file. We do NOT rely
   on live SSH while FakeNet is up; we reconnect and pull AFTER FakeNet stops.
2. BELT-AND-SUSPENDERS — add the control peer (SLIRP gateway / control subnet) to
   FakeNet's HostBlackList so our SSH traffic is never diverted (lets us monitor).
3. Optional — a dedicated second control NIC on its own subnet that FakeNet ignores.

## The sequence (exact order)
1. RESET: terminate any Procmon, clear old logs; verify clean state.
2. START FAKENET: launch FakeNet-NG (network capture + fake services begin).
3. REGSHOT SHOT 1: baseline registry + filesystem, BEFORE running the malware.
4. START PROCMON: begin capture to a backing file.
5. DETONATE: run the malware; start the timer.
6. OBSERVE: let it run 3-4 minutes (configurable) — network + system activity.
7. STOP PROCMON: finalize/terminate the capture; export to CSV.
8. REGSHOT SHOT 2: (FakeNet still running) take shot 2, compare, export the diff.
9. STOP FAKENET: collect the pcap + HTTP logs.
10. MEMORY: dump unpacked payload / key material from memory (for re-static + recovery).
11. ANALYZE PCAP (host, tshark): HTTP streams (requests/hosts/URIs), WebSocket (WS),
    DNS queries, TCP conversations -> network IOCs.
12. PARSE BEHAVIOR: Procmon CSV + Regshot diff -> files written, registry changes,
    persistence, dropped payloads, processes spawned.
13. FEED BACK: dumped payload -> re-static (reveal hidden functions/URLs/config);
    update the Proof of Compromise.

## Tool automation
- FakeNet-NG: `fakenet` (elevated); captures land in its folder (packets_*.pcap, http_*.txt).
  Configure HostBlackList for the control peer.
- Procmon (headless): start `Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile log.pml`;
  finalize `Procmon.exe /Terminate`; export `Procmon.exe /OpenLog log.pml /SaveAs log.csv`.
- Regshot: GUI only. Automated equivalent = reg export (HKLM/HKCU) + filesystem walk with
  hashes before/after, then diff. Keep Regshot GUI for manual runs. (Noriben, a scriptable
  Procmon wrapper, is the clean automated behavioral option.)
- tshark (headless Wireshark): `tshark -r cap.pcap -Y "http.request" -T fields -e http.host -e http.request.uri`;
  `-Y websocket`; `-Y dns.flags.response==0 -T fields -e dns.qry.name`; `-q -z conv,tcp`.

## Logging (required, built: nanalyst/runlog.py)
- run.log + run.jsonl: every command sent (host/guest), every input, every artifact,
  timestamped; secrets redacted.
- checklist.json: the full ordered phase list (see runlog.PHASES) tracked
  pending -> running -> done/failed/skipped, so no phase is ever forgotten.
- Every worker calls RunLog + Checklist; the Proof of Compromise cites the run log.
