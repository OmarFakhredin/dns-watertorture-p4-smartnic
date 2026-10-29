#!/usr/bin/env python3
"""                                                                        

                                                                              
                                                                            
                                                                               
                                                                             
                                                                         

                                                                                        
"""

from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import sys
from typing import BinaryIO
import zlib


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, 1_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000, 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, 1),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, 1),
}
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
MAX_FRAME_BYTES = 16 * 1024 * 1024


class PacketIssue(ValueError):
    """A named exclusion from event output, not an inferred DNS verdict."""

    def __init__(self, reason: str, category: str = "malformed") -> None:
        super().__init__(reason)
        self.reason = reason
        self.category = category


def _need(data: bytes, offset: int, length: int, reason: str) -> None:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise PacketIssue(reason)


def _label_text(label: bytes) -> str:
    result = []
    for byte in label:
        if 65 <= byte <= 90:
            byte += 32
        # Escaping separators makes an embedded dot distinct from a label break.
        if 33 <= byte <= 126 and byte not in (46, 92):
            result.append(chr(byte))
        else:
            result.append(f"\\{byte:03d}")
    return "".join(result)


def decode_name(data: bytes, start: int) -> tuple[str, int]:
    """                                                                         

                                                                            
                                                                             
                                                                             
                                                                           
                                                                          
                                                                              
    """
    position = start
    next_offset = None
    visited: set[int] = set()
    labels = []
    expanded_size = 1  # Root terminator.
    pointer_count = 0
    while True:
        _need(data, position, 1, "dns_name_truncated")
        if position in visited:
            raise PacketIssue("dns_name_pointer_loop")
        visited.add(position)
        length = data[position]
        if length & 0xC0 == 0xC0:
            _need(data, position, 2, "dns_pointer_truncated")
            pointer_count += 1
            if pointer_count > 128:
                raise PacketIssue("dns_name_pointer_limit")
            target = ((length & 0x3F) << 8) | data[position + 1]
            if target >= len(data):
                raise PacketIssue("dns_pointer_out_of_bounds")
            if next_offset is None:
                next_offset = position + 2
            position = target
            continue
        if length & 0xC0:
            raise PacketIssue("dns_reserved_label_encoding", "unsupported")
        position += 1
        if length == 0:
            return ".".join(labels) if labels else ".", (
                position if next_offset is None else next_offset
            )
        _need(data, position, length, "dns_label_truncated")
        expanded_size += length + 1
        if expanded_size > 255:
            raise PacketIssue("dns_name_too_long")
        labels.append(_label_text(data[position : position + length]))
        position += length


def parse_dns_message(data: bytes) -> dict:
    """                                                                        

                                                                          
                                                                         
                                                              
    """
    _need(data, 0, 12, "dns_header_truncated")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", data)
    opcode = (flags >> 11) & 15
    if opcode != 0:
        raise PacketIssue(f"dns_opcode_{opcode}", "unsupported")
    if qd != 1:
        raise PacketIssue(f"dns_question_count_{qd}", "unsupported")
    qname, offset = decode_name(data, 12)
    _need(data, offset, 4, "dns_question_truncated")
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    offset += 4
    extended_rcode = 0
    opt_seen = False
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            owner, offset = decode_name(data, offset)
            _need(data, offset, 10, "dns_rr_header_truncated")
            rrtype, _rrclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            _need(data, offset, rdlength, "dns_rr_data_truncated")
            end = offset + rdlength
            if rrtype == 41:
                if section != "additional" or owner != ".":
                    raise PacketIssue("dns_invalid_opt_location")
                if opt_seen:
                    raise PacketIssue("dns_multiple_opt_records")
                opt_seen = True
                extended_rcode = (ttl >> 24) & 255
                edns_version = (ttl >> 16) & 255
                if edns_version != 0:
                    raise PacketIssue(f"dns_edns_version_{edns_version}", "unsupported")
                option_offset = offset
                while option_offset < end:
                    if option_offset + 4 > end:
                        raise PacketIssue("dns_edns_option_header_truncated")
                    _code, option_length = struct.unpack_from("!HH", data, option_offset)
                    option_offset += 4 + option_length
                    if option_offset > end:
                        raise PacketIssue("dns_edns_option_data_truncated")
            offset = end
    if offset != len(data):
        raise PacketIssue("dns_trailing_bytes")
    is_response = bool(flags & 0x8000)
    result = {
        "kind": "response" if is_response else "query",
        "qname": qname,
        "dns_id": ident,
        "qtype": qtype,
        "qclass": qclass,
    }
    if is_response:
        result["rcode"] = (extended_rcode << 4) | (flags & 15)
    return result


def _udp_dns_payload(frame: bytes) -> tuple[bytes, dict]:
    _need(frame, 0, 14, "ethernet_header_truncated")
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    vlan_count = 0
    while ethertype in VLAN_TYPES:
        vlan_count += 1
        if vlan_count > 2:
            raise PacketIssue("vlan_depth_gt_2", "unsupported")
        _need(frame, offset, 4, "vlan_header_truncated")
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ethertype == 0x86DD:
        raise PacketIssue("ipv6", "unsupported")
    if ethertype != 0x0800:
        raise PacketIssue(f"ethernet_type_0x{ethertype:04x}", "ignored")
    _need(frame, offset, 20, "ipv4_header_truncated")
    version = frame[offset] >> 4
    ihl = (frame[offset] & 15) * 4
    if version != 4 or ihl < 20:
        raise PacketIssue("ipv4_invalid_header")
    _need(frame, offset, ihl, "ipv4_options_truncated")
    total_length = struct.unpack_from("!H", frame, offset + 2)[0]
    if total_length < ihl:
        raise PacketIssue("ipv4_invalid_total_length")
    _need(frame, offset, total_length, "ipv4_payload_truncated")
    fragment = struct.unpack_from("!H", frame, offset + 6)[0]
    if fragment & 0x3FFF:                                                    
        raise PacketIssue("ipv4_fragmentation", "unsupported")
    protocol = frame[offset + 9]
    if protocol == 6:
        raise PacketIssue("tcp", "unsupported")
    if protocol != 17:
        raise PacketIssue(f"ipv4_protocol_{protocol}", "ignored")
    ip_end = offset + total_length
    udp_offset = offset + ihl
    if udp_offset + 8 > ip_end:
        raise PacketIssue("udp_header_truncated")
    sport, dport, udp_length, _checksum = struct.unpack_from("!HHHH", frame, udp_offset)
    if udp_length < 8 or udp_offset + udp_length != ip_end:
        raise PacketIssue("udp_invalid_length")
    if sport != 53 and dport != 53:
        raise PacketIssue("udp_non_dns_port", "ignored")
    metadata = {
        "src": str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16])),
        "dst": str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20])),
        "sport": sport,
        "dport": dport,
        "transport": "udp",
    }
    return frame[udp_offset + 8 : ip_end], metadata


def _new_audit(input_path: Path) -> dict:
    return {
        "schema_version": 1,
        "input": str(input_path),
        "status": "ok",
        "capture": {},
        "counts": dict.fromkeys(
            (
                "frames", "events", "queries", "responses", "nxdomain_responses",
                "other_responses", "qr0", "qr1", "unsupported", "malformed",
                "ignored", "truncated", "timestamp_reversals",
                "duplicate_frame_observations", "duplicate_event_observations",
                "container_errors",
            ),
            0,
        ),
        "unsupported_reasons": Counter(),
        "malformed_reasons": Counter(),
        "ignored_reasons": Counter(),
        "dns_opcodes": Counter(),
        "errors": [],
        "coverage": {
            "container": "classic PCAP, optionally gzip-compressed",
            "supported": "Ethernet, up to two VLAN tags, unfragmented IPv4/UDP port 53; DNS opcode 0, one question, EDNS version 0",
            "unsupported": ["other link types", "IPv6", "TCP", "IP fragmentation", "more than two VLAN tags", "nonzero DNS opcode", "question count other than one", "nonzero EDNS version"],
            "qname": "ASCII lowercase; no terminal dot except root; nonplain label bytes escaped as backslash plus three decimal digits",
            "order": "capture-record order; timestamps are not sorted",
            "qr_counts": "QR flags observed in DNS-port UDP payloads with a complete 12-byte DNS header, including later rejected DNS messages",
            "response_counts": "accepted response events only; NXDOMAIN means full EDNS-aware RCODE exactly 3",
            "duplicates": "All observations retained. Frame repeats use SHA-256 of captured frame bytes, excluding timestamp. Event repeats use every emitted field except time_ns and frame_no. Repetition does not prove network duplication.",
            "checksums_validated": False,
            "missing_responses_inferred": False,
            "max_captured_frame_bytes": MAX_FRAME_BYTES,
        },
    }


def _record_issue(audit: dict, issue: PacketIssue) -> None:
    audit["counts"][issue.category] += 1
    audit[f"{issue.category}_reasons"][issue.reason] += 1
    if issue.category == "malformed" and "truncated" in issue.reason:
        audit["counts"]["truncated"] += 1


def _container_error(audit: dict, reason: str, frame_no: int | None = None) -> None:
    audit["status"] = "error"
    audit["counts"]["container_errors"] += 1
    error = {"reason": reason}
    if frame_no is not None:
        error["frame_no"] = frame_no
    audit["errors"].append(error)


def _discard(stream: BinaryIO, length: int) -> bool:
    while length:
        chunk = stream.read(min(length, 64 * 1024))
        if not chunk:
            return False
        length -= len(chunk)
    return True


def convert_pcap(input_path: str | Path, events_path: str | Path) -> dict:
    """                                                            

                                                                             
                                                                          
                                                                     
    """
    input_path, events_path = Path(input_path), Path(events_path)
    if input_path.resolve() == events_path.resolve() or (
        input_path.exists() and events_path.exists() and input_path.samefile(events_path)
    ):
        raise ValueError("Input and events paths must differ")
    audit = _new_audit(input_path)
    counts = audit["counts"]
    frame_fingerprints: set[bytes] = set()
    event_fingerprints: set[bytes] = set()
    previous_time = None
    opener = gzip.open if input_path.suffix.lower() == ".gz" else open
    try:
        with opener(input_path, "rb") as source, events_path.open("x", encoding="utf-8") as events:
            header = source.read(24)
            if len(header) < 24:
                _container_error(audit, "pcap_global_header_truncated")
                return audit
            if header[:4] not in PCAP_MAGICS:
                _container_error(audit, "unsupported_capture_format_or_magic")
                return audit
            endian, resolution, factor = PCAP_MAGICS[header[:4]]
            major, minor, _zone, _sigfigs, snaplen, network = struct.unpack(endian + "HHiIII", header[4:])
            audit["capture"] = {
                "format": "classic_pcap",
                "byte_order": "little" if endian == "<" else "big",
                "timestamp_resolution": "nanosecond" if factor == 1 else "microsecond",
                "version": f"{major}.{minor}",
                "snaplen": snaplen,
                "linktype": network,
            }
            if (major, minor) != (2, 4):
                _container_error(audit, "unsupported_pcap_version")
                return audit
            if snaplen == 0:
                _container_error(audit, "pcap_zero_snaplen")
                return audit
            if network != 1:
                audit["capture"]["linktype_supported"] = False
            else:
                audit["capture"]["linktype_supported"] = True
            while True:
                record = source.read(16)
                if not record:
                    break
                if len(record) < 16:
                    _container_error(audit, "pcap_record_header_truncated", counts["frames"] + 1)
                    break
                counts["frames"] += 1
                frame_no = counts["frames"]
                seconds, fraction, captured_length, original_length = struct.unpack(endian + "4I", record)
                time_ns = seconds * 1_000_000_000 + fraction * factor
                if fraction < resolution:
                    if previous_time is not None and time_ns < previous_time:
                        counts["timestamp_reversals"] += 1
                    previous_time = time_ns
                if captured_length > MAX_FRAME_BYTES:
                    _record_issue(audit, PacketIssue("capture_record_size_limit", "unsupported"))
                    if not _discard(source, captured_length):
                        _container_error(audit, "pcap_record_payload_truncated", frame_no)
                        break
                    continue
                frame = source.read(captured_length)
                if len(frame) != captured_length:
                    _record_issue(audit, PacketIssue("pcap_record_payload_truncated"))
                    _container_error(audit, "pcap_record_payload_truncated", frame_no)
                    break
                digest = hashlib.sha256(frame).digest()
                if digest in frame_fingerprints:
                    counts["duplicate_frame_observations"] += 1
                frame_fingerprints.add(digest)
                try:
                    if fraction >= resolution:
                        raise PacketIssue("pcap_invalid_timestamp_fraction")
                    if captured_length > snaplen or captured_length > original_length:
                        raise PacketIssue("pcap_invalid_record_lengths")
                    if captured_length < original_length:
                        raise PacketIssue("pcap_snapshot_truncated")
                    if network != 1:
                        raise PacketIssue(f"linktype_{network}", "unsupported")
                    dns_payload, metadata = _udp_dns_payload(frame)
                    if len(dns_payload) >= 12:
                        flags = struct.unpack_from("!H", dns_payload, 2)[0]
                        counts["qr1" if flags & 0x8000 else "qr0"] += 1
                        audit["dns_opcodes"][str((flags >> 11) & 15)] += 1
                    dns = parse_dns_message(dns_payload)
                    event = {"time_ns": time_ns, **dns, **metadata, "frame_no": frame_no}
                    event_key = {key: value for key, value in event.items() if key not in ("time_ns", "frame_no")}
                    event_digest = hashlib.sha256(json.dumps(event_key, sort_keys=True, separators=(",", ":")).encode()).digest()
                    if event_digest in event_fingerprints:
                        counts["duplicate_event_observations"] += 1
                    event_fingerprints.add(event_digest)
                    events.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                    counts["events"] += 1
                    if dns["kind"] == "query":
                        counts["queries"] += 1
                    else:
                        counts["responses"] += 1
                        counts["nxdomain_responses" if dns["rcode"] == 3 else "other_responses"] += 1
                except PacketIssue as exc:
                    _record_issue(audit, exc)
    except (OSError, EOFError, zlib.error) as exc:
        _container_error(audit, f"io_error: {type(exc).__name__}: {exc}")
    return audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Classic .pcap or .pcap.gz")
    parser.add_argument("--events", required=True, type=Path, help="Output DNS event JSONL")
    parser.add_argument("--audit", required=True, type=Path, help="Output coverage and response audit JSON")
    args = parser.parse_args(argv)
    paths = [args.input.resolve(), args.events.resolve(), args.audit.resolve()]
    if len(set(paths)) != len(paths):
        parser.error("--input, --events and --audit must be different paths")
    if args.events.exists() or args.audit.exists():
        parser.error("Use fresh --events and --audit paths; existing evidence is preserved")
    for index, path in enumerate(paths):
        for other in paths[index + 1 :]:
            if path.exists() and other.exists() and path.samefile(other):
                parser.error("--input, --events and --audit must not refer to the same file")
    audit = convert_pcap(args.input, args.events)
    try:
        with args.audit.open("x", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        print(f"Cannot write audit: {exc}", file=sys.stderr)
        return 2
    counts = audit["counts"]
    print(f"status={audit['status']}; {counts['events']} DNS events; {counts['queries']} queries; "
          f"{counts['responses']} responses ({counts['nxdomain_responses']} NXDOMAIN); "
          f"{counts['unsupported']} unsupported and {counts['malformed']} malformed frames.")
    return 0 if audit["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
