# References

Literature behind token scanning and secret detection. BibTeX in
`references.bib`. All citations verified against primary sources. Generated
2026-06-01.

## Secret leakage: measurement & developer practice

- Meli, McNiece, Reaves (2019). *How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories.* NDSS. https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/ — first large-scale leakage study; origin of many copied token regexes (incl. this repo's earliest patterns).
- Krause, Klemmer, Huaman, Wermke, Acar, Fahl (2023). *Pushed by Accident: A Mixed-Methods Study on Strategies of Handling Secret Information in Source Code Repositories.* USENIX Security. https://www.usenix.org/conference/usenixsecurity23/presentation/krause — why secrets get committed despite tooling.
- Rahman, Imtiaz, Storey, Williams (2022). *Why secret detection tools are not enough: It's not just about false positives — An industrial case study.* Empirical Software Engineering 27(3). https://doi.org/10.1007/s10664-021-10109-y — bypass mechanisms, not just FP, drive leaks.

## Detection tools: evaluation & datasets

- Basak, Cox, Reaves, Williams (2023). *A Comparative Study of Software Secrets Reporting by Secret Detection Tools.* ESEM. https://arxiv.org/abs/2307.00714 — precision/recall benchmark of 9 tools; the numbers cited in `sniffer-audit.md`.
- Basak, Neil, Reaves, Williams (2023). *SecretBench: A Dataset of Software Secrets.* MSR. https://arxiv.org/abs/2303.06729 — labeled benchmark (97,479 candidates, 15,084 true) for evaluating scanners.

## Detection techniques (regex, entropy, ML, data-flow)

- Sinha, Saha, Dhoolia, Padhye, Mani (2015). *Detecting and Mitigating Secret-Key Leaks in Source Code Repositories.* MSR, pp. 396–400. https://dl.acm.org/doi/10.5555/2820518.2820570 — early pattern + program-slicing approach.
- Saha, Denning, Srikumar, Kasera (2020). *Secrets in Source Code: Reducing False Positives using Machine Learning.* COMSNETS. https://doi.org/10.1109/COMSNETS48256.2020.9027350 — voting classifier over a regex prefilter.
- Lounici, Rosa, Negri, Trabelsi, Önen (2021). *Optimizing Leak Detection in Open-source Platforms with Machine Learning Techniques.* ICISSP, pp. 145–159. https://doi.org/10.5220/0010238101450159 — basis of SAP credential-digger; reports ~80% FP without ML filtering.
- Ding, Khakshoor, Paglierani, Rajpal (2020). *Sniffing for Codebase Secret Leaks with Known Production Secrets in Industry.* arXiv:2008.05997. https://arxiv.org/abs/2008.05997 — match against known live secrets as ground truth.
- Basak, English, Ogura, Kambara, Reaves, Williams (2025). *AssetHarvester: A Static Analysis Tool for Detecting Secret-Asset Pairs in Software Artifacts.* ICSE. https://arxiv.org/abs/2403.19072 — data-flow pairing of a secret with the asset it unlocks; 0% FP on the pairing.

## LLM-based detection (recent)

- Ahmed, Rahman, Wahab, Uddin, Shahriyar (2024). *Secret Leak Detection in Software Issue Reports using LLMs: A Comprehensive Evaluation.* arXiv:2410.23657 (to appear, MSR 2026). https://arxiv.org/abs/2410.23657
- Rahman, Ahmed, Wahab, Sohan, Shahriyar (2025). *Secret Breach Detection in Source Code with Large Language Models.* arXiv:2504.18784. https://arxiv.org/abs/2504.18784

## Standards & specifications (used by this repo)

- Jones, Bradley, Sakimura (2015). *RFC 7519: JSON Web Token (JWT).* IETF. https://datatracker.ietf.org/doc/html/rfc7519
- Josefsson (2006). *RFC 4648: The Base16, Base32, and Base64 Data Encodings.* IETF. https://datatracker.ietf.org/doc/html/rfc4648
- Josefsson, Leonard (2015). *RFC 7468: Textual Encodings of PKIX, PKCS, and CMS Structures.* IETF. https://datatracker.ietf.org/doc/html/rfc7468

## Tools & industry references (non-archival)

Not papers; cited for pattern provenance and the methodology comparison in
`sniffer-audit.md`.

- gitleaks. https://github.com/gitleaks/gitleaks — RE2 regex rules; primary modern source for this repo's patterns.
- TruffleHog. https://github.com/trufflesecurity/trufflehog — 700+ detectors with live verification.
- detect-secrets (Yelp). https://github.com/Yelp/detect-secrets — entropy-centric plugins; opt-in verification.
- Nosey Parker (Praetorian). https://github.com/praetorian-inc/noseyparker — ~188 high-precision regex rules, no verification.
- GitHub secret scanning — supported patterns. https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns — issuer-defined, validity-checked.
- GitGuardian, *State of Secrets Sprawl* (annual report). https://www.gitguardian.com/state-of-secrets-sprawl-report — industry leakage volume figures.
