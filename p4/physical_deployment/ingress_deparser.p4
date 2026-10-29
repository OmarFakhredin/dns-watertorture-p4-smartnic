




control SwitchIngressDeparser(
        packet_out pkt,
        inout Parsed_packet hdr,
        in    ig_metadata_t ig_md,
        in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}
