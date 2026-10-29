#!/usr/bin/env python3
"""                                                                          """
import argparse
import hashlib
import json
from pathlib import Path
from word_reference import PublicSuffix, Reference, NS, file_hash


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    root = Path(__file__).resolve().parent
    config = dict(mode="coupon_reconstruction", window_seconds=3600, window_anchor_ns=0,
                  heavy_domains=["hosting.example"],
                  heavy_domains_provenance="Synthetic fixture, not WORD's missing original list",
                  input_capture_scope="Synthetic in-memory fixtures only, not measured traffic",
                  domain_mapping_provenance="Bundled PSL plus explicit synthetic example domains",
                  psl_private_rules="include",
                  domain_overrides=["attack.example", "hosting.example", "nominal.example"],
                  comparison_status="assumption_bound_reconstruction", seed="synthetic-demo-1",
                  coupon_types=32, coupon_threshold=23, inverse_coupon_probability=8192,
                  first_coupon_keep_probability=1.0)
    ref = Reference(config, PublicSuffix((root / "data/public_suffix_list.dat").read_text()))
    for i in range(25000):
        tag = hashlib.sha256(("synthetic-name-%d" % i).encode()).hexdigest()[:26]
        base = i * NS // 20
                                                                                     
        ref.consume(dict(time_ns=base, kind="query", qname=tag + ".attack.example"))
        ref.consume(dict(time_ns=base + 1, kind="query", qname=tag + ".hosting.example"))
        ref.consume(dict(time_ns=base + 2, kind="response", rcode=3,
                         qname=tag + ".hosting.example"))
        ref.consume(dict(time_ns=base + 3, kind="query", qname="www.nominal.example"))
    result = ref.result()
    assert result["audit"]["events"] == 100000
    assert result["audit"]["eligible_nxdomain_responses"] == 25000
    assert result["audit"]["eligible_queries"] == 50000
    assert all(x["domain"] != "nominal.example" for x in result["alerts"])
    result["demonstration_scope"] = "SYNTHETIC_FUNCTIONAL_FIXTURE_NOT_USER_DATA_NOT_WORD_REPRODUCTION"
    result["generator_sha256"] = file_hash(__file__)
    result["reference_sha256"] = file_hash(root / "word_reference.py")
    result["psl_sha256"] = file_hash(root / "data/public_suffix_list.dat")
    with args.out.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"scope": result["demonstration_scope"], "events": 100000,
                      "alert_count": result["alert_count"], "output": str(args.out)}))


if __name__ == "__main__":
    main()
