# WORD-derived offline reference

This package implements a configurable Python **reconstruction**, a classic-PCAP
DNS response audit, and an exact-count diagnostic. It does not contain original
WORD source or a completed comparison on your full dataset. No hardware is used.

Genuine DNS responses provide NXDOMAIN through
QR=1 and full RCODE=3. A returned WTQ/WTR query, missing return, timeout, SERVFAIL,
or attack label does not provide this information.

## Run locally

Python 3.8 or later, standard library only. Commands below run in this extracted
directory. Use fresh output paths; model output never overwrites an existing file.

```powershell
python -B -m unittest -v test_word_reference test_pcap_dns
python -B demo.py --out synthetic_demo_new.json
python -B pcap_dns.py --input original_bidirectional.pcap.gz --events dns_events.jsonl --audit dns_audit.json
```

Review `dns_audit.json` before evaluation. The adapter accepts Ethernet (up to two
VLAN tags), IPv4, unfragmented UDP/53 and standard one-question DNS. It supports
compressed names and EDNS extended RCODE. TCP, IPv6, IP fragments, PCAPNG and other
unsupported input are explicitly excluded, not silently treated as benign.
Checksum validity is not established. Extend input coverage if your captures need
it, then validate the extension. Capture duplicates remain; choose and document a
single observation point instead of double-counting ingress and egress.

Copy `profiles/word_reconstruction.pending.json` to a new configuration. Fill the
null fields from the dataset and a predeclared reconstruction protocol: window
anchor, heavy-domain list/provenance, domain mapping, private-suffix policy,
capture scope and first-coupon
keep probability. Null values intentionally prevent an accidental supposedly
faithful run with guessed parameters. An explicit empty heavy list means only an
ordinary-domain scenario, not the complete published method.

```powershell
python -B word_reference.py --events dns_events.jsonl --config declared_config.json --psl data/public_suffix_list.dat --out word_results.json
```

`--events` also accepts `.jsonl.gz`. Times are integer nanoseconds. Events must be
nondecreasing and at or after the declared anchor; reversals fail instead of being
silently reordered. The bundled PSL includes private suffixes. Its header records the snapshot
version and upstream commit; it is not the unreported 2021 table.
Predeclare justified domain overrides before evaluating labels; this matters for
multi-label suffixes and shared hosting. For example, treating `blogspot.com` as
a heavy domain while including its private-suffix rule requires an explicit
domain override; otherwise the model rejects that unreachable heavy entry.

## Outputs and interpretation

- Alerts: domain, timestamp, event/query ordinal, eligible distinct names, coupons.
- Per-domain/window ordinary queries, responses and observed NXDOMAIN counts.
- Additional counters after first coupon, for descriptive use only. WORD does
  not publish the supplemental ratio-alert thresholds; none are invented here.
- Diagnostic matching uses endpoints, ports, transport, DNS ID, QNAME, QTYPE and
  QCLASS. Reused keys/retransmissions remain ambiguous; missing observations are
  not automatically loss or NXDOMAIN. Matching does not gate WORD's response path.
- Input/config/source hashes and explicit assumptions. There is no suppression
  field: WORD's published experiment reports alerts, not a blocking policy.

The coupon reconstruction uses 32 coupon types, a 23-coupon alert and probability
1/8192 per type, derived from the public BeauCoup compiler. SHA256 supplies an
independent uniform bucket mapping, not the original CRC/P4 mapping. The initial
coin, window implementation, list and hash choices must be reported. Run several
predeclared seeds and coin settings rather than selecting a favorable outcome.

`exact_count.pending.json` offers a 10,000-distinct diagnostic. It is not an exact
WORD implementation. Both modes count label sequences, preserve distinct-name
semantics across repeats, and exclude a bare domain's empty subdomain (an explicit
reference choice). Exact sets retained for auditing do not represent hardware
memory cost. The model has no state-table collisions, parser hardware limits,
capacity drops, clock synchronization model or physical timing prediction.

## External inputs

Supply your own original bidirectional captures or ordered DNS event records
and a completed, declared configuration. No dataset, saved comparison, evidence
receipt or handoff history is included in this core distribution. Missing
responses must not be inferred to be NXDOMAIN; defense-filtered responses are
not uncensored inputs. The demo is a synthetic functional check only.

## Sources and provenance

- WORD, SIGCOMM 2021: https://www.openu.ac.il/personal_sites/shir-landau-feibish/papers/2021_DNS_WORD_SIGCOMM.pdf
- BeauCoup: https://github.com/Princeton-Cabernet/BeauCoup/tree/2cc29526caa7b6c37da240afa05d0d9375985ded
- DNS: https://www.rfc-editor.org/rfc/rfc1035
- PSL: https://publicsuffix.org/list/public_suffix_list.dat

The independent Python model and adapter do not copy BeauCoup code. The bundled
PSL retains its Mozilla Public License notice. No WORD paper text, credentials,
private keys or raw user captures are redistributed.
