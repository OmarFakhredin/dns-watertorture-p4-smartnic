# DNS water-torture mitigation with P4 and SmartNICs

This repository contains the paper's core implementation and reference code,
not a complete experimental evidence archive. A P4 pipeline extracts DNS
features, applies a frozen random forest, and selects queries for inspection.
A C++ SmartNIC worker tracks per-zone history, confirms sustained suspicious
activity, and emits feedback for switch enforcement. End-to-end operation also
requires site-specific forwarding and a feedback controller; those deployment
and experiment orchestration tools are outside this package.

The confirmation rule, capacities, expiry, exemptions and model weights are
unchanged. The retained source binding identifies the qualified ARM binary as
`df41ca369b9a3bbbe9f829883947731a6702a9d9adafd1bc89ef0fe35855f649`.
This is a source distribution, not that binary: previously cleaned comments and
the portable build file mean source exports have different hashes from original
build inputs. No learned confirmation model is substituted.

## Contents

| Folder | Contents |
| --- | --- |
| `p4/deployment/` | Main TNA program, `basic.p4`, and its project includes. |
| `p4/physical_deployment/` | Physical Tofino program, `flowrest_phys_1017a.p4`, and includes; retained port bindings are 140. |
| `native/` | Confirmation core, DPDK service, ordered event replay and portable Makefile. |
| `tests/native/` | The single policy fixture required by the native Makefile. |
| `rf/` | Frozen forest and table JSON, inference helper, generator and validation source. |
| `integration/p4_loader/` | Final RF table loader and its process/network-namespace ownership check. |
| `reproduction/ctu_word/word_scale/reference/` | Our Python WORD reference reconstruction, PCAP adapter, tests, configuration templates and Public Suffix List. |

Unused `monitor.p4`, older classifier-layout loaders, historical native launch
guards and qualification manifests are omitted. No captures or private datasets
are included.

## Local checks

Use Python 3.8+ for the standard-library helpers and WORD tests, and a C++17
compiler for the native core. The following direct commands were checked with
Python 3.13 and MinGW g++ on Windows; run them from the repository root in
PowerShell with `g++` on PATH. Build outputs stay outside source directories.

```powershell
New-Item -ItemType Directory -Force build | Out-Null
g++ -O3 -std=c++17 -Wall -Wextra -Inative native/core.cpp tests/native/surplus128_policy_fixture.cpp -o build/policy_fixture.exe
./build/policy_fixture.exe
g++ -O3 -std=c++17 -Wall -Wextra -DORIGINAL_SOURCE native/core.cpp native/event_replay.cpp -o build/event_replay.exe
python -B -c "import subprocess; subprocess.run(['build/event_replay.exe'], input='', text=True, check=True)"
python -B -c "import json,sys; sys.path.insert(0,'rf'); import forest_model as f, generate_flowrest as g; assert json.loads(json.dumps(g.build(f.load()))) == json.load(open('rf/flowrest_tables.json')); print('RF tables match frozen forest')"
Push-Location reproduction/ctu_word/word_scale/reference
python -B -m unittest -v test_word_reference test_pcap_dns
Pop-Location
```

The replay smoke check above supplies no events; it is not a traffic experiment.
For real replay, feed ordered lines on stdin: `S <time_seconds>` for a sweep or
`Q <time_seconds> <ordinal> <qname_hex> <client> <dns_id> <qtype> <zone_hash> <subdomain_hash> <tier> <overflow>`
for an observation. QNAME is the hex encoding of the textual name. Preserve
recorded event times and sweeps; the harness does not recreate P4 selection,
packet transport or controller installation delays. Always compile this harness
with `-DORIGINAL_SOURCE`, as the supplied Makefile does.

On Linux with GNU Make and g++, the corresponding build targets are
`make -C native all` and `make -C native check`. The Makefile prerequisites were
checked; validation used the direct compiler commands above.

## Requirements and use

P4 builds use the Tofino SDE/compiler and its TNA architecture includes. Packet
processing uses a Tofino switch or software model, a BlueField DPU running Linux,
and DPDK with its NIC driver and `pkg-config` metadata. The native DPDK build
command is `make -C native dpdk`. Deployment requires site-specific forwarding
and feedback control.

The table loader uses the vendor `bfrt_grpc.client` module. It retains its explicit
site-tool guard and process/network-namespace ownership check. The frozen paper
mapping uses `--rule probability` with `rf/flowrest_tables.json`. Configure the
SDK paths and runtime identity for the deployment before use.

For portable RF checking, use the `build(model)` API command above. The retained
generator and full validator CLIs use their original training/template input
layout; inspect their arguments and input paths before using them.

WORD's tests use Python's standard library. Dataset replay uses your own captures
or event records and a completed configuration from the included templates.
See its [README](reproduction/ctu_word/word_scale/reference/README.md) for formats
and reconstruction assumptions.

## Attribution

Our RF mapping follows ideas from Akem, Gucciardo and Fiore, *Flowrest: Practical
Flow-Level Inference in Programmable Switches with Random Forests*, IEEE INFOCOM
2023 ([official repository](https://github.com/nds-group/Flowrest)). The DNS-specific
generator and loaders are project implementations; no upstream Flowrest source
or copied upstream README is included here. The retained audit found no
substantive copied Flowrest implementation, but the provenance of short common
constructs in inherited P4 templates still needs author clarification. This
minimal export is not a new licensing clearance.

The WORD comparator is our reference reconstruction, not the authors' original
implementation. Its assumptions and sources are documented in its README.
The bundled Public Suffix List retains its Mozilla Public License 2.0 notice,
upstream URL, version and commit in `data/public_suffix_list.dat` within that
reference directory. No project license has been added; third-party notices
continue to apply.
