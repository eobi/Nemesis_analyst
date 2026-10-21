# Security & responsible use

Nemesis Analyst is defensive tooling for malware analysts and reverse engineers.

- Analyse only samples you are **authorised** to handle.
- Run dynamic analysis and detonation only inside an **isolated, disposable VM** with no route to
  anything you care about. Revert the VM after every sample.
- The repository ships **no malware**. Example folders contain only hashes and detection rules.

## Reporting a vulnerability

Found a security issue in the tool itself? Please open a private security advisory via GitHub
(**Security → Report a vulnerability**) rather than a public issue.
