# Changelog

## 1.0.0

- Dynamic unpacking under x32dbg/x64dbg in a throwaway VM: early pause, API hooks, anti-debug bypass, payload and PE capture.
- One PDF per run, in its own `cases/<uuid>_<malware>/` folder, plus a detection package (IOCs, YARA, Sigma, Suricata, STIX).
- Malware category with a "what to track" checklist, dump-by-dump content analysis, file-encryption analysis with a decryptor proven by round trip, author fingerprints.
- Optional detonation (FakeNet, Procmon, Regshot) and `--observe` mode.
- Runs survive a closed terminal and rescue themselves on interrupt. `--finalize` rebuilds reports without a VM.
- MCP server with background jobs: `setup_check`, `start_analysis`, `start_detonation`, `run_status`, `run_summary`, `get_report`, `get_iocs`.
  Dynamic tools are gated; detonation is off unless the server owner enables it.
