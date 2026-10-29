








#include <core.p4>
#include <tna.p4>
#include "physical_binding.p4"

#include "headers.p4"

#include "ingress_parser.p4"
#include "ingress.p4"
#include "ingress_deparser.p4"

#include "egress_parser.p4"
#include "egress.p4"
#include "egress_deparser.p4"




@pa_no_overlay("ingress", "p.inline_outer.dst")
@pa_no_overlay("ingress", "p.inline_outer.src")
@pa_no_overlay("ingress", "p.inline_outer.etherType")
@pa_no_overlay("ingress", "p.inline_ctrl.magic")
@pa_no_overlay("ingress", "p.inline_ctrl.version")
@pa_no_overlay("ingress", "p.inline_ctrl.header_len")
@pa_no_overlay("ingress", "p.inline_ctrl.code")
@pa_no_overlay("ingress", "p.inline_ctrl.flags")
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
        ) pipe;

Switch(pipe) main;
