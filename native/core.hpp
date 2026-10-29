#pragma once
#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace dns {
using Bytes = std::vector<uint8_t>;
using Mac = std::array<uint8_t, 6>;
enum class Risk { low, medium, high };
enum class Verdict { cleared, attack };
const char *risk_name(Risk risk);
Mac parse_mac(const std::string &text);
std::string hex(const uint8_t *data, size_t size);
inline std::string hex(const Bytes &b) { return hex(b.data(), b.size()); }
inline std::string hex(const std::string &s) {
    return hex(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}
Bytes unhex(const std::string &text);
std::string json_string(const std::string &text);

struct Observation {
    std::string qname;
    std::string client;
    uint16_t dns_id = 0, qtype = 0, zone_hash = 0, subdomain_hash = 0;
    uint8_t tier = 0;
    bool overflow = false;
};
struct Hashes { uint16_t zone = 0, subdomain = 0; bool overflow = false; };
Hashes switch_hashes(const std::string &name);
Observation decode_wtq(const uint8_t *frame, size_t size);
void rewrite_return(uint8_t *frame, size_t size, const Mac &dst, const Mac &src);
Bytes make_return(const uint8_t *frame, size_t size, const Mac &dst, const Mac &src);
Bytes make_heartbeat(const Mac &dst, const Mac &src);
Bytes encode_policy(const Mac &dst, const Mac &src, uint8_t op, uint64_t session,
                    uint64_t sequence, const std::string &zone, uint32_t ttl_ms,
                    uint64_t epoch_ns);
bool eligible_zone(const std::string &zone);
std::pair<std::string, std::string> registrable_zone(const std::string &name);

struct Config {
    // Retained-evidence budgets are independent of packet rate.
    static constexpr size_t observations_per_zone = 8192, observations_global = 65536;
    static constexpr size_t max_decoded_name_bytes = 1020, max_client_bytes = 15;
    unsigned bucket_count = 12, max_zones = 1024, max_subdomains = 4096;
    unsigned max_clients = 1024, eval_every = 8, min_samples = 8;
    unsigned attack_evals = 3, clear_evals = 2, min_distinct = 64;
    double bucket_seconds = 10, zone_ttl = 600, min_unique_fraction = .90;
    bool experimental_distributed = false;
    unsigned sustained_completed_buckets = 2;
    void validate() const;
};
struct Bucket {
    int64_t slot = 0;
    uint64_t queries = 0, novel_queries = 0;
    std::unordered_map<std::string, unsigned> subs, clients;
};
struct Zone;
struct RetainedObservation {
    Zone *zone;
    int64_t slot;
    uint64_t sequence;
    // References to interned unordered-map keys remain valid across rehashes.
    const std::string *sub, *client;
    bool novel_at_admission = false;
};
using ObservationHistory = std::list<RetainedObservation>;
struct Zone {
    std::string name;
    double last_seen = 0;
    std::deque<Bucket> buckets;
    std::deque<ObservationHistory::iterator> observations;
    std::unordered_map<std::string, unsigned> sub_refs, client_refs;
    // Incremental statistics of nonempty members of sub_refs.
    std::set<std::string> ordered_subs;
    std::unordered_map<std::string, unsigned> shapes, first_labels, stems;
    uint64_t length_sum = 0, length_squared_sum = 0;
    uint64_t samples = 0, total_queries = 0, queries = 0, novel_admissions = 0;
    unsigned attack_streak = 0, clear_streak = 0;
    bool truncated = false;
    Risk risk = Risk::low;
};
struct View {
    bool present = false, truncated = false;
    Risk risk = Risk::low;
    uint64_t distinct = 0, clients = 0, queries = 0, samples = 0, novel_admissions = 0;
};
class Runtime {
public:
    struct CapacityStats {
        uint64_t admitted = 0, name_evicted = 0, client_evicted = 0;
        uint64_t zone_budget_evicted = 0, global_budget_evicted = 0;
        uint64_t expired = 0, discarded = 0, peak_retained = 0;
    };
    explicit Runtime(Config config = {});
    bool observe(const Observation &packet, double now);
    void sweep(double now);
    bool confirmed(const std::string &zone) const;
    Verdict confirm(const Zone &zone) const;
    Verdict original_confirm(const Zone &zone) const;
    Verdict uncliented_confirm(const Zone &zone) const;
    bool collection_evidence(const std::string &zone) const;
    bool original_evidence(const std::string &zone) const;
    bool distributed_evidence(const std::string &zone) const;
    bool sustained_activity(const Zone &zone) const;
    View view(const std::string &zone) const;
    void set_sweep_audit(std::function<void(double)> f) { sweep_audit_=std::move(f); }
    size_t zone_count() const { return zones_.size(); }
    const Config &config() const { return config_; }
    size_t retained_count() const { return history_.size(); }
    const CapacityStats &capacity_stats() const { return capacity_; }
    std::string debug_json() const;
    std::string capacity_json() const;
private:
    struct Entry { std::unique_ptr<Zone> zone; std::list<std::string>::iterator lru; };
    Config config_;
    double last_sweep_;
    double clock_now_ = 0;
    std::function<void(double)> sweep_audit_;
    std::list<std::string> lru_;
    std::unordered_map<std::string, Entry> zones_;
    ObservationHistory history_;
    CapacityStats capacity_;
    void discard(const std::string &name);
    void expire(Zone &zone, int64_t slot);
    void evaluate(Zone &zone);
    void remove_oldest(Zone &zone);
    static void add_sub(Zone &zone, const std::string &sub);
    static void remove_sub(Zone &zone, const std::string &sub);
};

class Policies {
public:
    using Send = std::function<void(uint8_t, const std::string &, const Bytes &)>;
    Policies(Runtime &runtime, Mac dst, Mac src, uint64_t session, Send send,
             unsigned renew_ms = 1000, unsigned ttl_ms = 5000);
    void tick(double now, uint64_t epoch_ns);
    void observe_zone(const std::string &zone, uint64_t epoch_ns);
    void close(uint64_t epoch_ns);
    uint64_t sequence() const { return sequence_; }
    size_t active_count() const { return active_.size(); }
private:
    Runtime &runtime_;
    Mac dst_, src_;
    uint64_t session_, sequence_ = 0;
    Send send_;
    unsigned renew_ms_, ttl_ms_;
    double next_tick_;
    std::list<std::string> known_;
    std::unordered_map<std::string, std::list<std::string>::iterator> known_index_;
    std::unordered_set<std::string> active_;
    void send(uint8_t op, const std::string &zone, unsigned ttl_ms, uint64_t epoch_ns);
    void forget(const std::string &zone);
};
}
