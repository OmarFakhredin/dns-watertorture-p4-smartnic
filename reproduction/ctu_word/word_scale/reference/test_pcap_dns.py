"""                                                                     

                                                                        
                                                                         
                             
"""

import gzip
import ipaddress
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import pcap_dns


def name_wire(name="MiXeD.Example.COM"):
    if name == ".":
        return b"\x00"
    labels = name.split(".") if isinstance(name, str) else name
    result = bytearray()
    for label in labels:
        label = label.encode("ascii") if isinstance(label, str) else label
        result.extend(bytes([len(label)]))
        result.extend(label)
    result.append(0)
    return bytes(result)


def dns_message(*, name="MiXeD.Example.COM", response=False, rcode=0,
                dns_id=0x1234, qtype=1, qclass=1, opcode=0, qdcount=1,
                answer=b"", ancount=0, additional=b"", arcount=0,
                question_wire=None):
    flags = (0x8000 if response else 0) | (opcode << 11) | (rcode & 15)
    flags |= 0x0100
    question = name_wire(name) if question_wire is None else question_wire
    return (struct.pack("!6H", dns_id, flags, qdcount, ancount, 0, arcount)
            + question + struct.pack("!HH", qtype, qclass)
            + answer + additional)


def opt_record(*, extended_rcode=0, version=0, options=b""):
    ttl = (extended_rcode << 24) | (version << 16)
    return b"\x00" + struct.pack("!HHIH", 41, 1232, ttl, len(options)) + options


def ethernet_ipv4(payload, *, sport=53000, dport=53, protocol=17,
                  fragment=0, vlan_tags=(), ethertype=0x0800,
                  udp_length=None, ip_total_length=None, ip_id=7,
                  src="192.0.2.10", dst="198.51.100.53"):
    if protocol == 17:
        udp_length = len(payload) + 8 if udp_length is None else udp_length
        ip_payload = struct.pack("!HHHH", sport, dport, udp_length, 0) + payload
    else:
        ip_payload = payload
    total_length = (20 + len(ip_payload) if ip_total_length is None
                    else ip_total_length)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, ip_id, fragment, 64,
        protocol, 0, ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed)
    header = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02"
    if vlan_tags:
        for tpid, tci in vlan_tags:
            header += struct.pack("!HH", tpid, tci)
    header += struct.pack("!H", ethertype)
    return header + ip_header + ip_payload


def pcap_bytes(records, *, endian="<", nanoseconds=False, linktype=1,
               snaplen=65535):
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    result = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0,
                                   snaplen, linktype))
    for record in records:
        sec, fraction, frame = record[:3]
        original_length = len(frame) if len(record) == 3 else record[3]
        result.extend(struct.pack(endian + "IIII", sec, fraction, len(frame),
                                  original_length))
        result.extend(frame)
    return bytes(result)


class PcapDnsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def convert(self, capture, *, compressed=False):
        index = len(list(self.directory.glob("events*.jsonl")))
        source = self.directory / ("input%d.pcap%s" % (index, ".gz" if compressed else ""))
        target = self.directory / ("events%d.jsonl" % index)
        source.write_bytes(gzip.compress(capture) if compressed else capture)
        audit = pcap_dns.convert_pcap(source, target)
        events = [json.loads(line) for line in target.read_text().splitlines()]
        return audit, events

    def test_query_and_response_schema_and_counts(self):
        query = ethernet_ipv4(dns_message(qtype=28, qclass=1))
        response = ethernet_ipv4(
            dns_message(response=True, rcode=3, qtype=28),
            src="198.51.100.53", dst="192.0.2.10", sport=53, dport=53000)
        other = ethernet_ipv4(dns_message(response=True, rcode=2), sport=53)
        audit, events = self.convert(pcap_bytes([
            (10, 123456, query), (10, 123457, response), (10, 123458, other)]))
        self.assertEqual(audit["status"], "ok")
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0], {
            "time_ns": 10_123_456_000, "kind": "query",
            "qname": "mixed.example.com", "src": "192.0.2.10",
            "dst": "198.51.100.53", "sport": 53000, "dport": 53,
            "transport": "udp", "dns_id": 0x1234, "qtype": 28,
            "qclass": 1, "frame_no": 1,
        })
        self.assertNotIn("rcode", events[0])
        self.assertEqual(events[1]["kind"], "response")
        self.assertEqual(events[1]["rcode"], 3)
        self.assertEqual(events[1]["src"], "198.51.100.53")
        self.assertEqual(events[1]["frame_no"], 2)
        self.assertEqual(events[2]["rcode"], 2)
        counts = audit["counts"]
        for field, expected in {"frames": 3, "events": 3, "queries": 1,
                                "responses": 2, "qr0": 1, "qr1": 2,
                                "nxdomain_responses": 1,
                                "other_responses": 1}.items():
            self.assertEqual(counts[field], expected, field)

    def test_compressed_question_and_compressed_rr_owner(self):
                                                                               
                                                                              
        owner = name_wire("COMPRESSED.Example")
        question = b"\xc0\x12"  # offset 18, after the question type/class
        rr = owner + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x01"
        second_rr = b"\xc0\x12" + struct.pack("!HHIH", 1, 1, 60, 4)
        second_rr += b"\xc0\x00\x02\x02"
        message = dns_message(response=True, question_wire=question,
                              answer=rr + second_rr, ancount=2)
        audit, events = self.convert(pcap_bytes([(1, 0, ethernet_ipv4(message))]))
        self.assertEqual(audit["counts"]["malformed"], 0)
        self.assertEqual(events[0]["qname"], "compressed.example")

    def test_compression_pointer_loop_and_out_of_bounds_are_malformed(self):
        frames = [ethernet_ipv4(dns_message(question_wire=pointer))
                  for pointer in (b"\xc0\x0c", b"\xc0\xff")]
        audit, events = self.convert(pcap_bytes([
            (1, index, frame) for index, frame in enumerate(frames)]))
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["malformed"], 2)
        self.assertEqual(sum(audit["malformed_reasons"].values()), 2)

    def test_reserved_name_encoding_is_rejected(self):
        frame = ethernet_ipv4(dns_message(question_wire=b"\x40"))
        audit, events = self.convert(pcap_bytes([(1, 0, frame)]))
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["unsupported"], 1)

    def test_expanded_name_length_is_bounded(self):
        # Four maximum-length labels exceed the DNS 255-byte expanded name.
        message = dns_message(name=[b"a" * 63] * 4)
        audit, events = self.convert(pcap_bytes([(1, 0, ethernet_ipv4(message))]))
        self.assertEqual(events, [])
        self.assertEqual(audit["malformed_reasons"]["dns_name_too_long"], 1)

    def test_name_presentation_lowercases_and_escapes_label_octets(self):
        message = dns_message(name=[b"A.B\\C\xff", b"EXAMPLE"])
        root = dns_message(name=".", dns_id=2)
        audit, events = self.convert(pcap_bytes([
            (1, 0, ethernet_ipv4(message)), (1, 1, ethernet_ipv4(root))]))
        self.assertEqual(audit["counts"]["events"], 2)
        self.assertEqual(events[0]["qname"], r"a\046b\092c\255.example")
        self.assertEqual(events[1]["qname"], ".")

    def test_one_and_two_vlan_tags(self):
        tag_sets = [((0x8100, 10),), ((0x88A8, 20), (0x8100, 30))]
        records = [(1, index, ethernet_ipv4(dns_message(), vlan_tags=tags))
                   for index, tags in enumerate(tag_sets)]
        audit, events = self.convert(pcap_bytes(records))
        self.assertEqual(audit["counts"]["events"], 2)
        self.assertEqual([event["qname"] for event in events],
                         ["mixed.example.com"] * 2)

    def test_third_vlan_tag_is_unsupported(self):
        tags = ((0x88A8, 1), (0x8100, 2), (0x8100, 3))
        frame = ethernet_ipv4(dns_message(), vlan_tags=tags)
        audit, events = self.convert(pcap_bytes([(1, 0, frame)]))
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["unsupported"], 1)

    def test_edns_extended_rcode_does_not_become_false_nxdomain(self):
        # Extended RCODE=1 and low RCODE=3 means 19, not NXDOMAIN (3).
        extended = dns_message(response=True, rcode=3, arcount=1,
                               additional=opt_record(extended_rcode=1))
        nxdomain = dns_message(response=True, rcode=3, arcount=1,
                              additional=opt_record())
        audit, events = self.convert(pcap_bytes([
            (1, 0, ethernet_ipv4(extended)),
            (1, 1, ethernet_ipv4(nxdomain))]))
        self.assertEqual([event["rcode"] for event in events], [19, 3])
        self.assertEqual(audit["counts"]["nxdomain_responses"], 1)
        self.assertEqual(audit["counts"]["other_responses"], 1)

    def test_edns_options_are_bounded_and_unknown_version_is_unsupported(self):
        valid_option = struct.pack("!HH", 65001, 3) + b"abc"
        valid = dns_message(response=True, arcount=1,
                            additional=opt_record(options=valid_option))
        truncated_option = struct.pack("!HH", 65001, 9) + b"abc"
        malformed = dns_message(response=True, arcount=1,
                                additional=opt_record(options=truncated_option))
        unsupported = dns_message(response=True, arcount=1,
                                  additional=opt_record(version=1))
        audit, events = self.convert(pcap_bytes([
            (1, 0, ethernet_ipv4(valid)), (1, 1, ethernet_ipv4(malformed)),
            (1, 2, ethernet_ipv4(unsupported))]))
        self.assertEqual(len(events), 1)
        self.assertEqual(audit["counts"]["malformed"], 1)
        self.assertEqual(audit["counts"]["unsupported"], 1)

    def test_unsupported_transport_and_fragmentation_are_counted(self):
        frames = [
            ethernet_ipv4(dns_message(), fragment=0x2000),
            ethernet_ipv4(dns_message(), fragment=1),
            ethernet_ipv4(b"\x00" * 20, protocol=6),
            ethernet_ipv4(b"\x00" * 40, ethertype=0x86DD),
        ]
        audit, events = self.convert(pcap_bytes([
            (1, index, frame) for index, frame in enumerate(frames)]))
        self.assertEqual(audit["status"], "ok")
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["unsupported"], 4)
        self.assertEqual(sum(audit["unsupported_reasons"].values()), 4)

    def test_unsupported_linktype_does_not_parse_ethernet_looking_payload(self):
        frame = ethernet_ipv4(dns_message())
        audit, events = self.convert(pcap_bytes([(1, 0, frame)], linktype=101))
        self.assertEqual(audit["status"], "ok")
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["unsupported"], 1)

    def test_nonstandard_opcode_and_question_count_are_unsupported(self):
        messages = [dns_message(opcode=1), dns_message(qdcount=0),
                    dns_message(qdcount=2, response=True)]
        audit, events = self.convert(pcap_bytes([
            (1, index, ethernet_ipv4(message))
            for index, message in enumerate(messages)]))
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["unsupported"], 3)
        self.assertEqual(audit["counts"]["qr0"], 2)
        self.assertEqual(audit["counts"]["qr1"], 1)

    def test_udp_outside_dns_ports_is_ignored(self):
        frame = ethernet_ipv4(dns_message(), sport=54000, dport=5353)
        audit, events = self.convert(pcap_bytes([(1, 0, frame)]))
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["ignored"], 1)
        self.assertEqual(sum(audit["ignored_reasons"].values()), 1)

    def test_malformed_udp_lengths_and_short_dns_are_rejected(self):
        frames = [ethernet_ipv4(dns_message(), udp_length=7),
                  ethernet_ipv4(dns_message(), udp_length=999),
                  ethernet_ipv4(b"\x00" * 11),
                  ethernet_ipv4(struct.pack("!6H", 1, 0, 1, 0, 0, 0))]
        audit, events = self.convert(pcap_bytes([
            (1, index, frame) for index, frame in enumerate(frames)]))
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["malformed"], 4)

    def test_snap_truncated_frame_is_not_reported_as_complete_dns(self):
        frame = ethernet_ipv4(dns_message())
        audit, events = self.convert(pcap_bytes([(1, 0, frame, len(frame) + 10)]))
        self.assertEqual(audit["status"], "ok")
        self.assertEqual(events, [])
        self.assertEqual(audit["counts"]["malformed"], 1)
        self.assertEqual(audit["counts"]["truncated"], 1)

    def test_truncated_record_and_global_header_have_container_errors(self):
        frame = ethernet_ipv4(dns_message())
        captures = [pcap_bytes([(1, 0, frame)])[:-7], b"\xd4\xc3\xb2\xa1"]
        for capture in captures:
            with self.subTest(length=len(capture)):
                audit, events = self.convert(capture)
                self.assertEqual(audit["status"], "error")
                self.assertEqual(events, [])
                self.assertGreaterEqual(audit["counts"]["container_errors"], 1)

    def test_corrupt_gzip_is_audited_instead_of_crashing(self):
        source = self.directory / "broken.pcap.gz"
        target = self.directory / "broken.jsonl"
        # A gzip header followed by a DEFLATE reserved block type.
        source.write_bytes(bytes.fromhex("1f8b08000000000002ff") + b"\xff" + b"\x00" * 8)
        audit = pcap_dns.convert_pcap(source, target)
        self.assertEqual(audit["status"], "error")
        self.assertEqual(audit["counts"]["container_errors"], 1)
        self.assertEqual(target.read_text(), "")

    def test_out_of_range_timestamp_fraction_is_rejected(self):
        frame = ethernet_ipv4(dns_message())
        audit, events = self.convert(pcap_bytes([(1, 1_000_000, frame)]))
        self.assertEqual(events, [])
        self.assertEqual(audit["malformed_reasons"]["pcap_invalid_timestamp_fraction"], 1)

    def test_timestamp_reversals_and_duplicates_are_preserved(self):
        frame = ethernet_ipv4(dns_message())
        audit, events = self.convert(pcap_bytes([(2, 0, frame), (1, 0, frame)]))
        self.assertEqual([event["time_ns"] for event in events],
                         [2_000_000_000, 1_000_000_000])
        self.assertEqual([event["frame_no"] for event in events], [1, 2])
        self.assertEqual(audit["counts"]["events"], 2)
        self.assertEqual(audit["counts"]["timestamp_reversals"], 1)
        self.assertEqual(audit["counts"]["duplicate_frame_observations"], 1)
        self.assertEqual(audit["counts"]["duplicate_event_observations"], 1)

    def test_repeated_event_keys_are_distinct_from_repeated_frame_bytes(self):
        first = ethernet_ipv4(dns_message(), ip_id=1)
        second = ethernet_ipv4(dns_message(), ip_id=2)
        audit, events = self.convert(pcap_bytes([(1, 0, first), (1, 1, second)]))
        self.assertEqual(len(events), 2)
        self.assertEqual(audit["counts"]["duplicate_frame_observations"], 0)
        self.assertEqual(audit["counts"]["duplicate_event_observations"], 1)

    def test_big_endian_nanoseconds_and_gzip(self):
        frame = ethernet_ipv4(dns_message())
        for endian in ("<", ">"):
            for nanos in (False, True):
                with self.subTest(endian=endian, nanoseconds=nanos):
                    fraction = 123456789 if nanos else 123456
                    capture = pcap_bytes([(9, fraction, frame)], endian=endian,
                                         nanoseconds=nanos)
                    audit, events = self.convert(capture, compressed=True)
                    expected = 9_000_000_000 + fraction * (1 if nanos else 1000)
                    self.assertEqual(audit["status"], "ok")
                    self.assertEqual(events[0]["time_ns"], expected)

    def test_cli_writes_events_and_audit(self):
        source = self.directory / "cli.pcap"
        events_path = self.directory / "cli.jsonl"
        audit_path = self.directory / "cli.audit.json"
        source.write_bytes(pcap_bytes([(1, 0, ethernet_ipv4(dns_message()))]))
        result = subprocess.run(
            [sys.executable, str(Path(pcap_dns.__file__).resolve()),
             "--input", str(source), "--events", str(events_path),
             "--audit", str(audit_path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(audit_path.read_text())["counts"]["queries"], 1)
        self.assertEqual(json.loads(events_path.read_text())["kind"], "query")


if __name__ == "__main__":
    unittest.main()
