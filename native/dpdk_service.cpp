#include "core.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <inttypes.h>
#include <limits>
#include <net/if.h>
#include <stdexcept>
#include <sys/random.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pause.h>
#include <rte_version.h>

namespace {
volatile sig_atomic_t stopping=0;
void on_signal(int) { stopping=1; }
double monotonic() {
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC,&ts)) throw std::runtime_error("CLOCK_MONOTONIC failed");
    return double(ts.tv_sec)+double(ts.tv_nsec)/1e9;
}
uint64_t epoch_ns() {
    timespec ts{};
    if (clock_gettime(CLOCK_REALTIME,&ts)) throw std::runtime_error("CLOCK_REALTIME failed");
    return uint64_t(ts.tv_sec)*1000000000ULL+uint64_t(ts.tv_nsec);
}
uint64_t random_session() {
    uint64_t session=0;
    for (;;) {
        size_t filled=0;
        while (filled<sizeof(session)) {
            ssize_t n=getrandom(reinterpret_cast<uint8_t *>(&session)+filled,sizeof(session)-filled,0);
            if (n<0 && errno==EINTR) continue;
            if (n<=0) throw std::runtime_error("session nonce generation failed");
            filled+=size_t(n);
        }
        if (session) return session;
    }
}
uint64_t read64(const uint8_t *b) { uint64_t v=0; for (unsigned i=0;i<8;++i) v=(v<<8)|b[i]; return v; }
unsigned number(const std::string &s,unsigned maximum=std::numeric_limits<unsigned>::max()) {
    size_t end=0;
    if (s.empty() || s[0]=='-') throw std::runtime_error("invalid unsigned option");
    unsigned long value=std::stoul(s,&end);
    if (end!=s.size() || value>maximum) throw std::runtime_error("option out of range");
    return unsigned(value);
}
struct Options {
    Options() { config.experimental_distributed=true; config.sustained_completed_buckets=2; }
    uint16_t port=0;
    std::string interface="p1",device="0000:03:00.1";
    dns::Mac node=dns::parse_mac("02:e3:54:92:ff:19");
    dns::Mac expected=dns::parse_mac("cc:40:f3:80:01:9b");
    dns::Config config;
    unsigned heartbeat_ms=250,heartbeat_log_every=20,log_every=1000;
    unsigned renew_ms=1000,ttl_ms=5000,tx_retry_us=1000,mbufs=8191;
    double duration=0;
};
void usage() {
    std::puts("dns_dpdk [EAL options] -- [service options]\n"
              "  --port 0 --interface p1 --expected-device 0000:03:00.1\n"
              "  --node-mac 02:e3:54:92:ff:19 --expected-mac cc:40:f3:80:01:9b\n"
              "  --confirmation-profile sustained-churn --confirmed-zone-feedback\n"
              "  --heartbeat-ms 250 --policy-renew-ms 1000 --policy-ttl-ms 5000\n"
              "  --history-seconds 120 --churn-min-distinct 64 --churn-min-unique-fraction .90\n"
              "  --max-zones 1024 --max-subdomains 4096 --max-clients 1024\n"
              "  --duration 0 --log-every 1000 --heartbeat-log-every 20\n"
              "  --tx-retry-us 1000 --mbufs 8191\n"
              "Use --app-help for help without initializing EAL. Single worker only.");
}
Options parse(int argc,char **argv) {
    Options o;
    for (int i=1;i<argc;++i) {
        std::string arg=argv[i];
        if (arg=="--confirmed-zone-feedback") continue;
        if (i+1>=argc) throw std::runtime_error("missing option value: "+arg);
        std::string value=argv[++i];
        if (arg=="--port") o.port=uint16_t(number(value,65535));
        else if (arg=="--interface") o.interface=value;
        else if (arg=="--expected-device") o.device=value;
        else if (arg=="--node-mac") o.node=dns::parse_mac(value);
        else if (arg=="--expected-mac") o.expected=dns::parse_mac(value);
        else if (arg=="--confirmation-profile") {
            if (value!="sustained-churn") throw std::runtime_error("only the accepted sustained-churn profile is implemented");
        } else if (arg=="--history-seconds") {
            unsigned n=number(value);
            if (!n || n%10) throw std::runtime_error("history must be a positive multiple of ten");
            o.config.bucket_count=n/10;
        } else if (arg=="--churn-min-distinct") o.config.min_distinct=number(value);
        else if (arg=="--churn-min-unique-fraction") o.config.min_unique_fraction=std::stod(value);
        else if (arg=="--max-zones") o.config.max_zones=number(value);
        else if (arg=="--max-subdomains") o.config.max_subdomains=number(value);
        else if (arg=="--max-clients") o.config.max_clients=number(value);
        else if (arg=="--heartbeat-ms") o.heartbeat_ms=number(value);
        else if (arg=="--heartbeat-log-every") o.heartbeat_log_every=number(value);
        else if (arg=="--log-every") o.log_every=number(value);
        else if (arg=="--policy-renew-ms") o.renew_ms=number(value);
        else if (arg=="--policy-ttl-ms") o.ttl_ms=number(value);
        else if (arg=="--tx-retry-us") o.tx_retry_us=number(value);
        else if (arg=="--mbufs") o.mbufs=number(value);
        else if (arg=="--duration") o.duration=std::stod(value);
        else throw std::runtime_error("unknown option: "+arg);
    }
    o.config.validate();
    if (!o.heartbeat_ms || !o.tx_retry_us || o.mbufs<1024 || o.duration<0 || !std::isfinite(o.duration))
        throw std::runtime_error("invalid service configuration");
    if (o.renew_ms<200 || o.renew_ms>2000 || o.ttl_ms<1000 ||
        o.ttl_ms<3*o.renew_ms || o.ttl_ms>10000) throw std::runtime_error("invalid policy lease configuration");
    return o;
}
void checked(int rc,const char *step) {
    if (rc<0) throw std::runtime_error(std::string(step)+": "+std::strerror(-rc));
}
struct MbufFree { void operator()(rte_mbuf *m) const { if (m) rte_pktmbuf_free(m); } };
using Mbuf=std::unique_ptr<rte_mbuf,MbufFree>;
struct Counters {
    uint64_t received=0,allowed=0,denied=0,invalid=0,ignored=0;
    uint64_t tx_failed=0,internal_failed=0,rx_dequeued=0,aborted_unclassified=0;
    uint64_t heartbeats=0,policies=0;
    double last_heartbeat=0,max_heartbeat_gap_ms=0;
};
class Port {
public:
    uint16_t id=0;
    bool opened=false,started=false;
    rte_mempool *pool=nullptr;
    rte_flow *flow=nullptr;
    dns::Mac mac{};
    rte_eth_stats baseline{};
    ~Port() {
        if (flow) { rte_flow_error error{}; rte_flow_destroy(id,flow,&error); }
        if (started) rte_eth_dev_stop(id);
        if (opened) rte_eth_dev_close(id);
        if (pool) rte_mempool_free(pool);
    }
    void initialize(const Options &o) {
        id=o.port;
        if (!rte_eth_dev_is_valid_port(id)) throw std::runtime_error("selected DPDK port is unavailable");
        rte_eth_dev_info info{};
        checked(rte_eth_dev_info_get(id,&info),"device capabilities");
        char name[RTE_ETH_NAME_MAX_LEN]{},interface[IF_NAMESIZE]{};
        checked(rte_eth_dev_get_name_by_port(id,name),"device name");
        if (!info.if_index || !if_indextoname(info.if_index,interface) || interface!=o.interface || name!=o.device)
            throw std::runtime_error("port does not match expected device/interface");
        if (!info.driver_name || std::strstr(info.driver_name,"mlx5")==nullptr)
            throw std::runtime_error("selected device is not an mlx5 port");
        rte_ether_addr hardware_mac{};
        checked(rte_eth_macaddr_get(id,&hardware_mac),"MAC query");
        std::copy_n(hardware_mac.addr_bytes,6,mac.begin());
        if (mac!=o.expected) throw std::runtime_error("DPU MAC does not match expected MAC");
        opened=true;
        rte_flow_error error{};
        if (rte_flow_isolate(id,1,&error)<0)
            throw std::runtime_error(std::string("flow isolation failed: ")+(error.message?error.message:"unknown"));
        uint16_t mtu=0;
        checked(rte_eth_dev_get_mtu(id,&mtu),"MTU query");
        uint32_t room=std::max<uint32_t>(4096,uint32_t(mtu)+RTE_PKTMBUF_HEADROOM+18);
        if (room>65535) throw std::runtime_error("MTU needs a segmented-mbuf configuration");
        pool=rte_pktmbuf_pool_create("dns_packet_pool",o.mbufs,256,0,uint16_t(room),rte_socket_id());
        if (!pool) throw std::runtime_error(std::string("mbuf pool: ")+rte_strerror(rte_errno));
        rte_eth_conf config{}; // Keep checksum, VLAN, and other byte-changing offloads disabled.
        config.rxmode.mtu=mtu;
        checked(rte_eth_dev_configure(id,1,1,&config),"configure one RX/TX queue");
        uint16_t rx_descriptors=512,tx_descriptors=512;
        checked(rte_eth_dev_adjust_nb_rx_tx_desc(id,&rx_descriptors,&tx_descriptors),"descriptor limits");
        rte_eth_rxconf rxconf=info.default_rxconf;
        rte_eth_txconf txconf=info.default_txconf;
        rxconf.offloads=0; txconf.offloads=0;
        checked(rte_eth_rx_queue_setup(id,0,rx_descriptors,rte_socket_id(),&rxconf,pool),"RX setup");
        checked(rte_eth_tx_queue_setup(id,0,tx_descriptors,rte_socket_id(),&txconf),"TX setup");
        checked(rte_eth_dev_start(id),"port start"); started=true;
        rte_flow_attr attr{}; attr.ingress=1;
        rte_flow_item_eth spec{},mask{};
        std::copy(mac.begin(),mac.end(),spec.dst.addr_bytes);
        std::fill_n(mask.dst.addr_bytes,6,0xff);
        spec.type=rte_cpu_to_be_16(0x88b9); mask.type=rte_cpu_to_be_16(0xffff);
        rte_flow_item pattern[2]{};
        pattern[0].type=RTE_FLOW_ITEM_TYPE_ETH; pattern[0].spec=&spec; pattern[0].mask=&mask;
        pattern[1].type=RTE_FLOW_ITEM_TYPE_END;
        rte_flow_action_queue queue{}; queue.index=0;
        rte_flow_action actions[2]{};
        actions[0].type=RTE_FLOW_ACTION_TYPE_QUEUE; actions[0].conf=&queue;
        actions[1].type=RTE_FLOW_ACTION_TYPE_END;
        if (rte_flow_validate(id,&attr,pattern,actions,&error)<0)
            throw std::runtime_error(std::string("WTQ1 flow validation: ")+(error.message?error.message:"unknown"));
        flow=rte_flow_create(id,&attr,pattern,actions,&error);
        if (!flow) throw std::runtime_error(std::string("WTQ1 flow creation: ")+(error.message?error.message:"unknown"));
        checked(rte_eth_stats_get(id,&baseline),"initial driver counters");
        std::printf("{\"event\":\"native_start\",\"dpdk\":%s,\"device\":%s,\"interface\":%s,"
                    "\"port\":%u,\"mtu\":%u,\"rx_descriptors\":%u,\"tx_descriptors\":%u,"
                    "\"profile\":\"sustained-churn\",\"history_seconds\":%u,\"min_distinct\":%u,"
                    "\"min_unique_fraction\":%.9g,\"started_epoch_ns\":%" PRIu64 "}\n",
                    dns::json_string(rte_version()).c_str(),dns::json_string(name).c_str(),
                    dns::json_string(interface).c_str(),id,mtu,rx_descriptors,tx_descriptors,
                    o.config.bucket_count*10,o.config.min_distinct,o.config.min_unique_fraction,epoch_ns());
    }
};
class Transmit {
    Port &port_; Counters &c_; unsigned retry_us_;
    std::vector<rte_mbuf *> pending_;
public:
    Transmit(Port &port,Counters &c,unsigned retry):port_(port),c_(c),retry_us_(retry) { pending_.reserve(32); }
    ~Transmit() { for (auto *p:pending_) if (p) { rte_pktmbuf_free(p); ++c_.tx_failed; } }
    void enqueue(Mbuf packet) { pending_.push_back(packet.get()); packet.release(); }
    void flush() {
        if (pending_.empty()) return;
        size_t sent=0; const double deadline=monotonic()+retry_us_/1e6;
        while (sent<pending_.size()) {
            uint16_t n=rte_eth_tx_burst(port_.id,0,pending_.data()+sent,uint16_t(pending_.size()-sent));
            for (size_t i=sent;i<sent+n;++i) pending_[i]=nullptr; // NIC owns accepted mbufs.
            sent+=n; c_.allowed+=n;
            if (sent==pending_.size()) { pending_.clear(); return; }
            if (monotonic()>=deadline) break;
            rte_pause();
        }
        for (auto *p:pending_) if (p) { rte_pktmbuf_free(p); ++c_.tx_failed; }
        pending_.clear();
        throw std::runtime_error("data TX queue stayed full; stopping heartbeats");
    }
    void control(const dns::Bytes &bytes) {
        flush(); // Preserve per-packet ordering relative to policy messages.
        Mbuf packet(rte_pktmbuf_alloc(port_.pool));
        if (!packet) throw std::runtime_error("control mbuf allocation failed");
        if (bytes.size()>65535) throw std::runtime_error("control frame is too large");
        void *buffer=rte_pktmbuf_append(packet.get(),uint16_t(bytes.size()));
        if (!buffer) throw std::runtime_error("control mbuf has insufficient room");
        std::memcpy(buffer,bytes.data(),bytes.size());
        const double deadline=monotonic()+retry_us_/1e6;
        do {
            rte_mbuf *pointer=packet.get();
            if (rte_eth_tx_burst(port_.id,0,&pointer,1)==1) { packet.release(); return; }
            rte_pause();
        } while (monotonic()<deadline);
        throw std::runtime_error("control TX queue stayed full; stopping heartbeats");
    }
};
struct RxBatch {
    std::array<rte_mbuf *,32> packets{};
    uint16_t count=0;
    Counters &c;
    explicit RxBatch(Counters &counter):c(counter) {}
    ~RxBatch() {
        for (unsigned i=0;i<count;++i) if (packets[i]) {
            rte_pktmbuf_free(packets[i]); ++c.aborted_unclassified;
        }
    }
    Mbuf take(unsigned i) { Mbuf p(packets[i]); packets[i]=nullptr; return p; }
};
void counter_line(const Counters &c) {
    std::printf("received=%" PRIu64 " allowed=%" PRIu64 " denied=%" PRIu64 " invalid=%" PRIu64 "\n",
                c.received,c.allowed,c.denied,c.invalid);
}
int serve(const Options &o) {
    Counters c;
    Port port; port.initialize(o);
    dns::Runtime runtime(o.config);
    runtime.set_sweep_audit([](double at) { std::printf("{\"event\":\"b2_effective_sweep\",\"monotonic\":%.17g}\n",at); });
    std::printf("{\"event\":\"b2_build\",\"variant\":\"NATIVE_SURPLUS128_V1\",\"candidate\":\"surplus128\",\"minimum_retained_observations\":128,\"maximum_score_observations\":512,\"novel_increment\":1,\"repeat_increment\":-9,\"score_threshold\":128,\"original_branch_retained\":false}\n");
    std::printf("%s\n",runtime.capacity_json().c_str());
    Transmit tx(port,c,o.tx_retry_us);
    const uint64_t session=random_session();
    dns::Policies policies(runtime,o.node,port.mac,session,
        [&](uint8_t op,const std::string &zone,const dns::Bytes &bytes) {
            tx.control(bytes); ++c.policies;
            std::printf("{\"event\":\"confirmed_policy_emitted\",\"op\":%u,\"zone\":%s,"
                        "\"session\":%" PRIu64 ",\"sequence\":%" PRIu64 ",\"ttl_ms\":%u,"
                        "\"emitted_epoch_ns\":%" PRIu64 "}\n",op,dns::json_string(zone).c_str(),
                        session,read64(bytes.data()+30),op==2?o.ttl_ms:0,read64(bytes.data()+42));
        },o.renew_ms,o.ttl_ms);
    auto heartbeat=dns::make_heartbeat(o.node,port.mac);
    const double start=monotonic();
    double next_heartbeat=start,next_sweep=start+1;
    int status=0;
    try {
        while (!stopping && (!o.duration || monotonic()-start<o.duration)) {
            double now=monotonic();
            if (now>=next_heartbeat) {
                tx.control(heartbeat);
                const double sent_at=monotonic();
                if (c.heartbeats) c.max_heartbeat_gap_ms=std::max(c.max_heartbeat_gap_ms,(sent_at-c.last_heartbeat)*1000);
                c.last_heartbeat=sent_at; ++c.heartbeats;
                next_heartbeat=sent_at+o.heartbeat_ms/1000.0;
                if (o.heartbeat_log_every && c.heartbeats%o.heartbeat_log_every==0)
                    std::printf("{\"event\":\"heartbeat_metrics\",\"sent\":%" PRIu64 ",\"max_gap_ms\":%.3f}\n",
                                c.heartbeats,c.max_heartbeat_gap_ms);
            }
            policies.tick(monotonic(),epoch_ns());
            RxBatch batch(c);
            batch.count=rte_eth_rx_burst(port.id,0,batch.packets.data(),uint16_t(batch.packets.size()));
            c.rx_dequeued+=batch.count;
            for (unsigned i=0;i<batch.count;++i) {
                Mbuf packet=batch.take(i);
                uint8_t ethernet[14]{};
                const uint8_t *header=static_cast<const uint8_t *>(rte_pktmbuf_read(packet.get(),0,14,ethernet));
                if (!header || header[12]!=0x88 || header[13]!=0xb9) { ++c.ignored; continue; }
                ++c.received;
                bool classified=false;
                try {
                    if (packet->nb_segs>1 && rte_pktmbuf_linearize(packet.get())<0)
                        throw std::runtime_error("cannot linearize received WTQ1");
                    uint8_t *data=rte_pktmbuf_mtod(packet.get(),uint8_t *);
                    const size_t size=rte_pktmbuf_pkt_len(packet.get());
                    dns::Observation p;
                    try { p=dns::decode_wtq(data,size); }
                    catch (const std::runtime_error &) { ++c.invalid; classified=true; continue; }
                    const double observed_at=monotonic();
                    bool denied=runtime.observe(p,observed_at);
                    std::string zone=dns::registrable_zone(p.qname).first;
                    policies.observe_zone(zone,epoch_ns());
                    auto evidence=runtime.view(zone);
                    std::printf("{\"event\":\"b2_observation\",\"ordinal\":%" PRIu64 ",\"monotonic\":%.17g,\"qname_hex\":\"%s\",\"client\":%s,\"dns_id\":%u,\"qtype\":%u,\"zone_hash\":%u,\"subdomain_hash\":%u,\"tier\":%u,\"overflow\":%s,\"denied\":%s,\"distinct\":%" PRIu64 ",\"clients\":%" PRIu64 ",\"queries\":%" PRIu64 ",\"risk\":%s,\"confirmed\":%s,\"original_predicate\":%s,\"distributed_predicate\":%s}\n",
                      c.received,observed_at,dns::hex(p.qname).c_str(),dns::json_string(p.client).c_str(),p.dns_id,p.qtype,p.zone_hash,p.subdomain_hash,p.tier,p.overflow?"true":"false",denied?"true":"false",evidence.distinct,evidence.clients,evidence.queries,dns::json_string(dns::risk_name(evidence.risk)).c_str(),runtime.confirmed(zone)?"true":"false",runtime.original_evidence(zone)?"true":"false",runtime.distributed_evidence(zone)?"true":"false");
                    if (denied) { ++c.denied; classified=true; }
                    else {
                        dns::rewrite_return(data,size,o.node,port.mac);
                        packet->ol_flags &= (RTE_MBUF_F_EXTERNAL | RTE_MBUF_F_INDIRECT);
                        packet->tx_offload=0;
                        tx.enqueue(std::move(packet)); classified=true;
                    }
                    if (c.received==1 || (o.log_every && c.received%o.log_every==0)) {
                        tx.flush(); counter_line(c);
                    }
                } catch (...) { if (!classified) ++c.internal_failed; throw; }
            }
            tx.flush();
            now=monotonic();
            if (now>=next_sweep) { runtime.sweep(now); next_sweep=now+1; }
            if (!batch.count) rte_pause();
        }
        tx.flush();
    } catch (const std::exception &e) {
        std::fprintf(stderr,"native service stopped: %s\n",e.what()); status=1;
    }
    try { policies.close(epoch_ns()); }
    catch (const std::exception &e) { std::fprintf(stderr,"policy cleanup: %s\n",e.what()); status=1; }
    counter_line(c);
    std::printf("%s\n",runtime.capacity_json().c_str());
    std::printf("{\"event\":\"native_final\",\"tx_failed\":%" PRIu64 ",\"internal_failed\":%" PRIu64 ","
                "\"ignored\":%" PRIu64 ",\"rx_dequeued\":%" PRIu64 ",\"aborted_unclassified\":%" PRIu64 ","
                "\"heartbeats\":%" PRIu64 ",\"policy_frames\":%" PRIu64 ",\"max_heartbeat_gap_ms\":%.3f,"
                "\"runtime_seconds\":%.6f,\"zones\":%zu,\"accounting_ok\":%s}\n",
                c.tx_failed,c.internal_failed,c.ignored,c.rx_dequeued,c.aborted_unclassified,c.heartbeats,c.policies,
                c.max_heartbeat_gap_ms,monotonic()-start,runtime.zone_count(),
                c.received==c.allowed+c.denied+c.invalid+c.tx_failed+c.internal_failed ? "true":"false");
    rte_eth_stats current{};
    if (rte_eth_stats_get(port.id,&current)==0)
        std::printf("{\"event\":\"driver_counter_delta\",\"ipackets\":%" PRIu64 ",\"opackets\":%" PRIu64 ","
                    "\"imissed\":%" PRIu64 ",\"ierrors\":%" PRIu64 ",\"oerrors\":%" PRIu64 ",\"rx_nombuf\":%" PRIu64 "}\n",
                    current.ipackets-port.baseline.ipackets,current.opackets-port.baseline.opackets,
                    current.imissed-port.baseline.imissed,current.ierrors-port.baseline.ierrors,
                    current.oerrors-port.baseline.oerrors,current.rx_nombuf-port.baseline.rx_nombuf);
    if (c.tx_failed || c.internal_failed || c.aborted_unclassified) status=1;
    return status;
}
}

int main(int argc,char **argv) {
    for (int i=1;i<argc;++i) if (std::strcmp(argv[i],"--app-help")==0) { usage(); return 0; }
    std::setvbuf(stdout,nullptr,_IOLBF,0);
    std::signal(SIGINT,on_signal); std::signal(SIGTERM,on_signal);
    int initialized=0,status=1;
    try {
        int parsed=rte_eal_init(argc,argv);
        if (parsed<0) throw std::runtime_error(std::string("EAL: ")+rte_strerror(rte_errno));
        initialized=1;
        Options options=parse(argc-parsed,argv+parsed);
        if (rte_lcore_count()!=1) throw std::runtime_error("this version requires exactly one enabled lcore");
        status=serve(options);
    } catch (const std::exception &e) { std::fprintf(stderr,"native startup/service error: %s\n",e.what()); }
    if (initialized && rte_eal_cleanup()<0) { std::fprintf(stderr,"EAL cleanup failed\n"); status=1; }
    return status;
}
