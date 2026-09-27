# Data provenance

## Deterministic synthetic telemetry

`scripts/generate_test_data.py` uses fixed times, explicit IDs, invented
identities, private/reserved addresses, and `.test` names. It does not execute
commands, contact sample destinations, or use nondeterministic system clocks
to construct events. All output is saved under `test-data/`.

`test-data/manifest.json` enumerates normal replay/validation datasets with
path, format, input count, expected alerts, purpose/class, source/license,
synthetic status, and checksum. `test-data/README.md` also enumerates benchmark,
security, parser-oracle, and Sigma inputs. Expected alert contracts are authored
independently of the engine.

```sh
.venv/bin/python scripts/generate_test_data.py          # restore generated files
.venv/bin/python scripts/generate_test_data.py --check  # isolated byte-for-byte comparison
```

Synthetic telemetry is MIT-licensed with the application. It is controlled test
material, not representative production telemetry or a measured false-positive
rate. A legitimate PowerShell download intentionally remains a positive
indicator case; the application does not pretend to infer intent.

## SigmaHQ rules

Two unmodified rules at
`07ec293a51695cb1131a2e05260247872b31e1e1` were downloaded on **2026-09-27**.
Source URLs, exact SHA-256 hashes, authors, and the pinned DRL 1.1 license
revision are in `test-data/sigma/provenance.json`.

The local files preserve original authors and comments, including the legitimate
installer false-positive note and real filter logic. The full license is
redistributed in `test-data/sigma/LICENSE.Detection.Rules.md`. Compilation and
matching retain the author, source URL, license, and original YAML. See
[Sigma support](sigma.md).

## OTRF public lab sample: actual use, limited purpose

- Repository: [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets).
- Pinned revision: `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`.
- Archive: `datasets/atomic/windows/execution/host/cmd_sharpview_pcre_net.zip`.
- Obtained: **2026-09-27**.
- Actually downloaded size: **28,626 bytes**.
- SHA-256: `314b1d08b9038dd327c8769c82564a44fd26fa1ba17ffa79e52b4683e2821dac`.
- Source member: `cmd_sharpview_pcre_net_2020-10-2920232423.json`, **267 JSONL rows**.
- Included adapted sample: **6 events** (two process creations, three DNS
  queries, one network connection).

The pinned root LICENSE explicitly grants the **MIT License**, copyright 2021
Open Threat Research Forge. It is saved as `test-data/public/LICENSE.OTRF`.
The upstream README also has an older contradictory GPL-3.0 footer despite its
MIT badge. This limited redistribution relies on the explicit root license at
the pinned revision and discloses the discrepancy rather than silently
relabeling the source.

The archive is read in memory with compressed/decompressed limits and a known
member name. Only supported event categories are selected. Flat provider and
timestamp fields are wrapped into explicit Windows JSON envelopes. Host/user
identities, addresses, domain names, and path prefixes are replaced
deterministically; process basenames, event IDs, original source row indices,
ports, protocol, and timezone-aware TimeCreated values are retained.

Message, command-line arguments, SID/GUID/hash/domain fields, and every
unlisted field are omitted. The original source's `UtcTime` is timezone-naive
and differs from `TimeCreated`; the adapter deliberately uses the latter
explicit-Z field. The included `raw_event` is therefore the **adapted export**,
not byte-for-byte original evidence.

This is controlled **attack-simulation lab data**, not a benign dataset.
Tests verify actual normalized fields and evidence. Zero bundled-rule matches
are expected on the selected, reduced observations, and are not presented as
proof of benignness, attack-detection success, or a public false-positive rate.

```sh
# Optional networked provenance reproduction; normal operation never downloads it.
.venv/bin/python scripts/prepare_public_sample.py
.venv/bin/python scripts/generate_test_data.py
```

Full source/download/license locations, transformations and measured source
counts are in `test-data/public/provenance.json`. No other public dataset is
claimed downloaded, tested, or redistributed.
