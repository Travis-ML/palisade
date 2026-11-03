# Examples

Everything the book shows that is not part of the `palisade` package itself. Nothing here is imported by the package.

| Folder | What it holds | Book |
|---|---|---|
| `lab/` | The Docker lab: compose file, Dockerfile, pinned requirements and image versions, the defensive and range OTel collectors, the range's Palisade configuration, range firewall rules, and `synth_siem.py`. Appendix I.1 expects `lab/` beside `palisade/` in your working directory, so copy it there: `cp -r palisade/examples/lab ./lab` | Appendix I |
| `labs/` | The scripts several chapter labs run (`lab05_run.py`, `lab06_route.py`, `lab26.py`, `lab27.py`). Run from your working directory with `PYTHONPATH=. python palisade/examples/labs/lab26.py`. `lab05_run.py` and `lab06_route.py` are excerpts that need the fakes and routing file the lab steps have you write | Chapters 5, 6, 26, 27 |
| `scripts/` | Worked examples and utilities: `sign_roe.py` (RoE signing), `run_first_loop.py` (the first governed run), the Chapter 2 round trip, the Chapter 3 injection experiment, the Chapter 10 worked example, the Chapter 15 PyRIT campaign, and the Chapter 25 scorer | Chapters 2, 3, 10, 11, 15, 25, Appendix H |
| `poc/` | The vendor proof-of-concept checks and the scorer | Chapter 25 |
| `config/`, `range/`, `deploy/`, `registry/`, `skills/`, `knowledge/`, `alerting/`, `lifecycle.yaml`, `promptfooconfig.yaml` | Configuration and manifests the chapters show at these paths | Chapters 4, 6, 7, 8, 15, 18, 19, 27, 28 |
| `github-workflows/` | The CI sketches (secret scan, assurance, repository review). They live here and not under `.github/` on purpose: placed in `.github/workflows/` of a repository they would run on every push. Copy one there when you mean to | Chapters 12, 15, 18 |
| `snippets/` | Excerpts and queries the book prints without a file path; see `snippets/INDEX.md` | all |
