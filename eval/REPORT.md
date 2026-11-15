# PhishGuard accuracy report

Reproduce:
```
python eval/fetch_data.py                 # builds data/dataset.csv from public sources
python eval/train.py                      # trains on the train split, prints honest held-out numbers
python eval/evaluate.py rules|ml|combined
python eval/eval_inspect.py 600 --unseen  # does page inspection help? (makes live web requests)
python tests/test_scoring.py && python tests/test_inspector.py
```

## Correction notice (read this first)
The first version of this report was **wrong in a way that mattered**. The safe-site test set contained only bare
domains (`bbc.co.uk`), never `www.bbc.co.uk`. The model learned "has `www.`/a subdomain = phishing" and the benchmark
could not see it, because train and test shared the same bias. In the shipped product, `www.bbc.co.uk` scored "dangerous".
It was found while testing link inspection, fixed by adding realistic `www.` / subdomain hosts to the safe data, and is now
guarded by `tests/test_scoring.py` (306 legitimate URL variants). All numbers below are from the corrected data.

## Part 1: URL + message rules + ML (hostname model)
**Data:** 20,000 phishing URLs (Phishing.Database ACTIVE list + OpenPhish) and 20,000 safe URLs (Tranco top-60k domains,
40% bare / 40% `www.` / 20% other subdomains, ~40% with sensitive-looking paths such as `/login`).
**Split:** by registrable domain, so no domain is in both train and test. Test = 3,872 phishing + 4,116 safe.
**Excluded:** live reputation lookups (OpenPhish, Cloudflare DNS), since the phishing set comes from those feeds.

| System | ROC-AUC | "Be careful" (>=25): detects / false alarms | "Likely a scam" (>=55): detects / false alarms |
|---|---|---|---|
| Rules only | 0.67 | 10.4% / 1.1% | 0.6% / 0.0% |
| ML hostname model only | 0.93 | 93.3% / 28.2% | 79.4% / 10.1% |
| **Rules + ML (shipped)** | 0.89 | **73.4% / 6.5%** | **47.8% / 0.8%** |

Precision at "Likely a scam": 98.3%. At "Be careful": 91.4%. The shipped model is retrained on all data; the table
describes the train-split model, so expect similar, not identical, performance.

## Part 2: link unmasking + page inspection
The server follows redirects and reads (never executes) the destination page. Tested on **600 phishing URLs from domains the
model never saw** (random sample of the Phishing.Database list) plus 600 safe URLs.

| | before inspection | after inspection |
|---|---|---|
| Detects at "Be careful" (all 600, incl. dead pages) | 73.3% | **75.2%** |
| False alarms at "Be careful" | 1.17% | 1.17% (no new ones) |
| Detects at "Likely a scam" | 46.3% | 46.3% (no change) |
| Live phishing pages missed by URL checks, rescued | | **11 of 64** |

**Honest reading:**
- Only ~24% of these phishing URLs (141/600) were still alive. Phishing dies within hours, so this list is mostly stale.
  Inspection can only help on pages that are alive when the user checks, which is the real use case, but we have no large free
  source of *fresh* phishing to measure that. The true gain for a link someone just received is probably higher; unproven.
- 11 of the rescues share one signature (pages titled "Microsoft page", likely one campaign). Treat the gain as real but
  narrow: one rule, one kit family. Do not extrapolate.
- Most "alive" pages returned 404/403 or a bot-check ("Just a moment..."): taken down, or cloaking from scanners.
  Many kits also draw their login with JavaScript, which we deliberately never run, so there is no form to see.
- Only 1 of 141 live phishing pages had a visible password field. Form-based rules rarely fire on real traffic;
  they are validated only by unit tests (`tests/test_inspector.py`, 33 checks), not by this benchmark.

## Known limitations
1. **Label noise:** Tranco popularity does not guarantee safety; some "false alarms" are genuinely bad sites.
2. **Synthetic safe paths/subdomains:** real traffic is more varied; real-world false-alarm rate may differ.
3. **Time drift:** phishing changes weekly. Retrain regularly (`fetch_data.py` + `train.py`).
4. **Hostname model noise:** long dictionary-word domains (e.g. `khanacademy.org/login`) can score "suspicious" (0.65% of
   well-known legitimate variants in `tests/test_scoring.py`); it never reaches "dangerous" on them.
5. **Cloaking:** phishing kits can show scanners a clean page. A clean inspection is not proof of safety.
6. **Message/SMS text detection** is not covered by any benchmark yet.
7. **Fresh-link accuracy is unmeasured** (see Part 2).

## Bugs found by this testing (all fixed)
- Bare-domain training bias flagged every `www.` link (above).
- ML model lazy-load race: concurrent first requests silently skipped the model. Now loaded under a lock at startup.
- Slow-drip HTTP server could hold a fetch far past the deadline (`read` vs `read1`). Now capped; covered by a test.
- "Hidden iframe" rule fired on the invisible Google Tag Manager frame found on most legitimate sites (false alarms
  rose 0.7% -> 6.7%). Now ignores `<noscript>` and known analytics/captcha hosts.
- Redirect scoring let the hostname model alone condemn destinations like `www.heart.org`. Now requires rules/blocklists to agree.
