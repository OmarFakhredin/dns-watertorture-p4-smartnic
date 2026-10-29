#!/usr/bin/env python3
"""                                                                               

                                                                             
                                                                            
"""
import argparse
from collections import Counter
from dataclasses import dataclass, field
import gzip
import hashlib
import json
from pathlib import Path


NS = 1_000_000_000
LABEL = "WORD_DERIVED_ASSUMPTION_BOUND_REFERENCE_NOT_ORIGINAL_WORD"


def name_labels(name):
    """Parse the adapter's DNS presentation form without splitting escaped dots."""
    if not isinstance(name, str):
        raise ValueError("qname must be a DNS presentation string")
    if name == ".":
        return ()
    out, current, i = [], bytearray(), 0
    while i < len(name):
        c = name[i]
        if c == "\\":
            if i + 3 >= len(name) or not name[i + 1:i + 4].isdigit():
                raise ValueError("Use three-digit DNS decimal escapes")
            value = int(name[i + 1:i + 4])
            if value > 255:
                raise ValueError("DNS escape out of range")
            current.append(value)
            i += 4
            continue
        if c == ".":
            if not current:
                raise ValueError("Empty interior label")
            out.append(bytes(current).lower())
            current.clear()
        else:
            if ord(c) > 127:
                raise ValueError("Use IDNA A-labels or DNS decimal escapes")
            current.append(ord(c))
        i += 1
    if current:
        out.append(bytes(current).lower())
    if not out or any(not 1 <= len(x) <= 63 for x in out):
        raise ValueError("Invalid label length")
    if sum(len(x) + 1 for x in out) + 1 > 255:
        raise ValueError("DNS wire name exceeds 255 bytes")
    return tuple(out)


def presentation(labels):
    if not labels:
        return "."
    return ".".join("".join(chr(c) if 33 <= c <= 126 and c not in (46, 92)
                             else "\\%03d" % c for c in label) for label in labels)


def wire(labels):
    return b"".join(bytes([len(x)]) + x for x in labels) + b"\0"


class PublicSuffix:
    def __init__(self, text, private_rules="include"):
        if private_rules not in ("include", "exclude"):
            raise ValueError("Explicit PSL private-rule policy must be include or exclude")
        self.private_rules = private_rules
        self.rules, self.exceptions = set(), set()
        private_section = False
        for raw in text.splitlines():
            raw = raw.strip()
            if "BEGIN PRIVATE DOMAINS" in raw:
                private_section = True
            if private_section and private_rules == "exclude":
                continue
            if not raw or raw.startswith("//"):
                continue
            exception = raw.startswith("!")
            raw = raw.lstrip("!")
            labels = tuple(x.encode("idna").lower() for x in raw.split("."))
            (self.exceptions if exception else self.rules).add(labels)

    def domain(self, labels):
        if not labels:
            return None
        suffix_length = 1                                    
        for i in range(len(labels)):
            suffix = labels[i:]
            if suffix in self.exceptions:
                suffix_length = len(suffix) - 1
                break
            if suffix in self.rules:
                suffix_length = max(suffix_length, len(suffix))
            if (b"*",) + labels[i + 1:] in self.rules:
                suffix_length = max(suffix_length, len(suffix))
        if len(labels) <= suffix_length:
            return None
        return labels[-suffix_length - 1:]


@dataclass
class DomainState:
    window: int
    domain: tuple
    heavy: bool
    queries: int = 0
    responses: int = 0
    nxdomain: int = 0
    eligible: int = 0
    distinct: set = field(default_factory=set)
    coupons: set = field(default_factory=set)
    first_coupon: bool = False
    tracked_queries: int = 0
    tracked_responses: int = 0
    tracked_nxdomain: int = 0
    tracked_start_ns: object = None
    alert: object = None


def validate_config(cfg):
    needed = ("mode", "window_seconds", "window_anchor_ns", "heavy_domains",
              "heavy_domains_provenance", "input_capture_scope", "seed",
              "domain_mapping_provenance", "psl_private_rules", "comparison_status")
    for key in needed:
        if key not in cfg or cfg[key] is None:
            raise ValueError("Explicit config required: " + key)
    if cfg["comparison_status"] != "assumption_bound_reconstruction":
        raise ValueError("Configuration must acknowledge reconstruction assumptions")
    if cfg["mode"] not in ("coupon_reconstruction", "exact_distinct_diagnostic"):
        raise ValueError("Unsupported mode")
    if cfg["psl_private_rules"] not in ("include", "exclude"):
        raise ValueError("psl_private_rules must explicitly be include or exclude")
    if type(cfg["window_anchor_ns"]) is not int:
        raise ValueError("window_anchor_ns must be an integer")
    if type(cfg["window_seconds"]) is not int or cfg["window_seconds"] <= 0:
        raise ValueError("window_seconds must be a positive integer")
    if not isinstance(cfg["heavy_domains"], list):
        raise ValueError("heavy_domains must be an explicit list, possibly empty")
    if not isinstance(cfg["seed"], str):
        raise ValueError("seed must be a string")
    for key in ("heavy_domains_provenance", "input_capture_scope", "domain_mapping_provenance"):
        if not isinstance(cfg[key], str) or not cfg[key].strip():
            raise ValueError("Missing provenance: " + key)
    if cfg["mode"] == "coupon_reconstruction":
        for key in ("coupon_types", "coupon_threshold", "inverse_coupon_probability"):
            if type(cfg.get(key)) is not int or cfg[key] <= 0:
                raise ValueError("Positive integer required: " + key)
        if not cfg["coupon_threshold"] <= cfg["coupon_types"] <= cfg["inverse_coupon_probability"]:
            raise ValueError("Require threshold <= types <= inverse probability")
        if cfg["inverse_coupon_probability"] & (cfg["inverse_coupon_probability"] - 1):
            raise ValueError("This reference supports power-of-two inverse probabilities")
        if cfg["inverse_coupon_probability"] > 2**256:
            raise ValueError("Inverse probability exceeds the SHA256 output range")
        p = cfg.get("first_coupon_keep_probability")
        if not isinstance(p, (float, int)) or not 0 <= p <= 1:
            raise ValueError("Explicit first-coupon keep probability in [0,1] required")
    elif type(cfg.get("exact_threshold")) is not int or cfg["exact_threshold"] <= 0:
        raise ValueError("Positive exact_threshold required")


class Reference:
    def __init__(self, config, psl):
        validate_config(config)
        self.cfg = config
        self.psl = psl
        if psl.private_rules != config["psl_private_rules"]:
            raise ValueError("Loaded PSL private-rule policy does not match configuration")
        self.heavy = {name_labels(x) for x in config["heavy_domains"]}
        self.overrides = sorted((name_labels(x) for x in config.get("domain_overrides", [])),
                                key=len, reverse=True)
        if any(not x for x in self.overrides):
            raise ValueError("Root cannot be a domain override")
        for heavy in self.heavy:
            if self.domain(heavy) != heavy:
                raise ValueError("Heavy domain %s cannot be selected by this PSL/grouping. "
                                 "Predeclare a justified domain override or revise the PSL policy."
                                 % presentation(heavy))
        self.states = {}
        self.finished = []
        self.alerts = []
        self.audit = Counter()
        self.pending = Counter()
        self.last_ns = None
        self.window = None
        self.event_ordinal = 0

    def domain(self, labels):
        for override in self.overrides:
            if len(labels) >= len(override) and labels[-len(override):] == override:
                return override
        return self.psl.domain(labels)

    def digest(self, purpose, value):
        return hashlib.sha256(self.cfg["seed"].encode() + b"\0" + purpose + b"\0" + value).digest()

    def coupon(self, subdomain):
                                                                              
        x = int.from_bytes(self.digest(b"coupon", wire(subdomain)), "big")
        x &= self.cfg["inverse_coupon_probability"] - 1
        return x if x < self.cfg["coupon_types"] else None

    def _match_audit(self, event, labels):
        fields = ("src", "dst", "sport", "dport", "transport", "dns_id", "qtype", "qclass")
        if not all(x in event for x in fields):
            self.audit["events_without_transaction_fields"] += 1
            return
        query = event["kind"] == "query"
        client = (event["src"], event["sport"]) if query else (event["dst"], event["dport"])
        server = (event["dst"], event["dport"]) if query else (event["src"], event["sport"])
        key = (client, server, event["transport"], event["dns_id"], labels,
               event["qtype"], event["qclass"])
        if query:
            self.pending[key] += 1
            if self.pending[key] > 1:
                self.audit["repeated_outstanding_query_key"] += 1
        elif self.pending[key] == 1:
            del self.pending[key]
            self.audit["responses_with_unique_preceding_query"] += 1
        elif self.pending[key] > 1:
            self.audit["responses_with_ambiguous_preceding_queries"] += 1
            self.audit["query_observations_in_ambiguous_groups"] += self.pending.pop(key)
        else:
            self.audit["responses_without_preceding_query"] += 1
                                                                                      

    def _finish_window(self):
        self.finished.extend(self._summary(s) for s in self.states.values())
        self.states.clear()

    def consume(self, event):
        now = event.get("time_ns")
        if type(now) is not int or now < self.cfg["window_anchor_ns"]:
            raise ValueError("time_ns must be integer >= configured window anchor")
        if self.last_ns is not None and now < self.last_ns:
            raise ValueError("Events out of time order; do not silently sort capture clocks")
        if event.get("kind") not in ("query", "response"):
            raise ValueError("kind must identify a parsed DNS query or response")
        if event["kind"] == "query" and "rcode" in event:
            raise ValueError("A query must not carry a manufactured response code")
        if event["kind"] == "response" and (type(event.get("rcode")) is not int or
                                                 not 0 <= event["rcode"] <= 4095):
            raise ValueError("Actual response requires the full integer RCODE")
        labels = name_labels(event["qname"])
        self.event_ordinal += 1
        self.last_ns = now
        window = (now - self.cfg["window_anchor_ns"]) // (self.cfg["window_seconds"] * NS)
        if window != self.window:
            self._finish_window()
            self.window = window
        kind = event["kind"]
        self.audit["events"] += 1
        self.audit[kind + "_events"] += 1
        if kind == "response":
            self.audit["response_rcode_%d" % event["rcode"]] += 1
        self._match_audit(event, labels)
        domain = self.domain(labels)
        if domain is None:
            self.audit["no_registrable_domain"] += 1
            return
        # Heavy list matches the selected domain, not every descendant by guesswork.
        s = self.states.setdefault(domain, DomainState(window, domain, domain in self.heavy))
        s.queries += kind == "query"
        s.responses += kind == "response"
        s.nxdomain += kind == "response" and event["rcode"] == 3
        subdomain = labels[:-len(domain)]
        eligible = bool(subdomain) and ((not s.heavy and kind == "query") or
                          (s.heavy and kind == "response" and event["rcode"] == 3))
        if not subdomain:
            self.audit["apex_events_excluded_from_distinct_count"] += 1
        if eligible:
            s.eligible += 1
            self.audit["eligible_nxdomain_responses" if s.heavy else "eligible_queries"] += 1
            s.distinct.add(subdomain)                                                     
            if self.cfg["mode"] == "exact_distinct_diagnostic":
                threshold = len(s.distinct) >= self.cfg["exact_threshold"]
                reason = "exact_distinct_diagnostic"
            else:
                coupon = self.coupon(subdomain)
                if coupon is not None and not s.first_coupon:
                                                                                        
                                                                                       
                                                                           
                    token = wire(domain) + window.to_bytes(8, "big") + self.event_ordinal.to_bytes(8, "big")
                    coin = int.from_bytes(self.digest(b"first-coupon-coin", token), "big")
                    numerator, denominator = float(self.cfg["first_coupon_keep_probability"]).as_integer_ratio()
                    if coin * denominator < numerator * 2**256:
                        s.first_coupon = True
                        s.tracked_start_ns = now
                    else:
                        self.audit["first_coupon_rejections"] += 1
                if coupon is not None and s.first_coupon:
                    s.coupons.add(coupon)
                threshold = len(s.coupons) >= self.cfg["coupon_threshold"]
                reason = "coupon_reconstruction"
            if threshold and s.alert is None:
                s.alert = {"domain": presentation(domain), "heavy": s.heavy,
                           "window_index": window, "time_ns": now,
                           "event_ordinal": self.event_ordinal,
                           "domain_query_ordinal": s.queries,
                           "eligible_ordinal": s.eligible,
                           "eligible_distinct_subdomains": len(s.distinct),
                           "coupon_count": len(s.coupons), "trigger": reason,
                           "frame_no": event.get("frame_no")}
                self.alerts.append(s.alert)
        if s.first_coupon:
            s.tracked_queries += kind == "query"
            s.tracked_responses += kind == "response"
            s.tracked_nxdomain += kind == "response" and event["rcode"] == 3

    def _summary(self, s):
        return {"domain": presentation(s.domain), "window_index": s.window,
                "heavy": s.heavy, "query_events": s.queries, "response_events": s.responses,
                "nxdomain_response_events": s.nxdomain, "eligible_events": s.eligible,
                "eligible_distinct_subdomains": len(s.distinct), "coupons": len(s.coupons),
                "response_evidence_status": ("no_responses_observed_not_evidence_of_NOERROR"
                                             if s.responses == 0 else "responses_observed"),
                "alert": s.alert, "post_first_coupon": {
                    "applicable": self.cfg["mode"] == "coupon_reconstruction",
                    "start_ns": s.tracked_start_ns, "queries": s.tracked_queries,
                    "responses": s.tracked_responses, "nxdomain": s.tracked_nxdomain}}

    def result(self):
        warnings = ["This reconstructs alert behavior under explicit assumptions; not original WORD.",
                    "No packet suppression, physical latency, throughput or SRAM usage is predicted.",
                    "Supplemental response-ratio alerts are unimplemented: published thresholds absent.",
                    "No state collisions/capacity drops or original P4 parser limits are modeled."]
        if not self.audit["response_events"]:
            warnings.append("No DNS responses: heavy-domain/response-dependent comparison unavailable.")
        if not self.heavy:
            warnings.append("Explicit empty heavy-domain list: ordinary-domain scenario only.")
        return {"model_label": LABEL, "status": "OFFLINE_REFERENCE_COMPLETE_NOT_DATASET_VALIDATION",
                "config": self.cfg, "audit": dict(self.audit),
                "unmatched_query_observations_at_end": sum(self.pending.values()),
                "matching_note": "Missing replies are capture observations, not DNS errors; ambiguous retransmissions are separate.",
                "window_semantics": "Nonoverlapping tumbling windows; explicit anchor; response counted at its arrival.",
                "alert_count": len(self.alerts), "alerts": self.alerts,
                "domains": self.finished + [self._summary(s) for s in self.states.values()],
                "limitations": warnings}


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--psl", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    validate_config(cfg)
    ref = Reference(cfg, PublicSuffix(args.psl.read_text(encoding="utf-8"), cfg["psl_private_rules"]))
    opener = gzip.open if args.events.suffix == ".gz" else open
    with opener(args.events, "rt", encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                ref.consume(json.loads(line))
            except Exception as exc:
                raise ValueError("Event line %d: %s" % (number, exc)) from exc
    result = ref.result()
    result["input_sha256"] = {"events": file_hash(args.events), "config": file_hash(args.config),
                              "psl": file_hash(args.psl), "reference_source": file_hash(__file__)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"status": result["status"], "events": ref.audit["events"],
                      "alerts": len(ref.alerts), "output": str(args.out)}))


if __name__ == "__main__":
    main()
