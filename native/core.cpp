#include "core.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace dns {
namespace {
bool letter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool digit(char c) { return c >= '0' && c <= '9'; }
char lower(char c) { return c >= 'A' && c <= 'Z' ? char(c + 32) : c; }
std::string lowercase(std::string s) { for (char &c : s) c = lower(c); return s; }
std::string trim_dots(std::string s) {
    size_t first = s.find_first_not_of('.');
    return first == std::string::npos ? "" : s.substr(first, s.find_last_not_of('.') - first + 1);
}
bool python_space(unsigned char c) { return (c >= 9 && c <= 13) || (c >= 28 && c <= 32); }
std::string strip_index(std::string s) {
    size_t first = 0, last = s.size();
    while (first < last && python_space(static_cast<unsigned char>(s[first]))) ++first;
    while (last > first && python_space(static_cast<unsigned char>(s[last-1]))) --last;
    s = lowercase(s.substr(first, last-first));
    size_t end = s.size();
    while (end && digit(s[end-1])) --end;
    if (end != s.size()) {
        if (end && (s[end-1] == '-' || s[end-1] == '_')) --end;
        s.resize(end);
    }
    return s;
}
std::vector<std::string> split(const std::string &s, bool skip_empty) {
    std::vector<std::string> result;
    size_t start = 0;
    for (;;) {
        size_t end = s.find('.', start);
        if (end == std::string::npos) end = s.size();
        if (!skip_empty || end > start) result.push_back(s.substr(start, end-start));
        if (end == s.size()) break;
        start = end + 1;
    }
    return result;
}
std::string join(const std::vector<std::string> &v, size_t start, size_t end) {
    std::string out;
    for (size_t i = start; i < end; ++i) { if (i != start) out += '.'; out += v[i]; }
    return out;
}
bool suffix_match(const std::string &s, const std::unordered_set<std::string> &list) {
    for (size_t start = 0;;) {
        if (list.count(s.substr(start))) return true;
        size_t dot = s.find('.', start);
        if (dot == std::string::npos) return false;
        start = dot + 1;
    }
}
const std::unordered_set<std::string> suffixes = {
    "ac.in", "co.in", "gov.in", "org.in", "net.in", "edu.in", "co.uk", "ac.uk",
    "gov.uk", "org.uk", "net.uk", "sch.uk", "com.au", "net.au", "org.au", "edu.au",
    "gov.au", "co.jp", "ac.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.cn",
    "com.hk", "co.nz", "com.sg", "com.tr", "com.sa"
};
const std::unordered_set<std::string> reserved = {
    "mshome.net", "local", "localdomain", "lan", "home", "internal", "intranet",
    "private", "corp", "in-addr.arpa", "ip6.arpa", "arpa", "test", "invalid",
    "example", "localhost", "onion", "workgroup"
};
const std::unordered_set<std::string> allowlist = {
    "akamaihd.net", "akamaiedge.net", "akamai.net", "akadns.net", "cloudfront.net",
    "cloudflare.com", "fastly.net", "edgekey.net", "edgesuite.net", "llnwd.net",
    "cdn77.org", "stackpathdns.com", "amazonaws.com", "elb.amazonaws.com",
    "azurewebsites.net", "windows.net", "googleusercontent.com", "appspot.com",
    "vk.me", "fbcdn.net", "whatsapp.net", "googlevideo.com", "ggpht.com", "gstatic.com",
    "icloud.com", "apple-dns.net", "twimg.com", "windowsupdate.com", "microsoft.com",
    "msn.com", "live.com", "skypedata.akadns.net", "teamviewer.com", "dropbox.com",
    "mcafee.com", "kaspersky-labs.com", "kaspersky.com", "sophosxl.net", "spamhaus.org",
    "senderbase.org"
};
uint16_t be16(const uint8_t *p) { return uint16_t((uint16_t(p[0]) << 8) | p[1]); }
void put32(Bytes &b, size_t i, uint32_t v) { for (int n=3; n>=0; --n) { b[i+n]=uint8_t(v); v >>= 8; } }
void put64(Bytes &b, size_t i, uint64_t v) { for (int n=7; n>=0; --n) { b[i+n]=uint8_t(v); v >>= 8; } }
void outer(Bytes &b, const Mac &dst, const Mac &src, uint16_t type) {
    std::copy(dst.begin(), dst.end(), b.begin());
    std::copy(src.begin(), src.end(), b.begin()+6);
    b[12] = uint8_t(type >> 8); b[13] = uint8_t(type);
}
uint16_t crc16(const Bytes &bytes) {
    uint16_t crc = 0xffff;
    for (uint8_t byte : bytes) {
        crc ^= uint16_t(byte) << 8;
        for (unsigned n = 0; n < 8; ++n)
            crc = uint16_t((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0));
    }
    return crc ^ 0xffff;
}
void field(Bytes &out, const std::string &label, unsigned width, unsigned base) {
    unsigned cursor = 0, offset = base;
    for (unsigned size = 1; size <= width; size *= 2) {
        if (label.size() & size) {
            size_t destination = out.size() - offset - size;
            for (unsigned n=0; n<size; ++n) out[destination+n] = uint8_t(label[cursor+n]);
            cursor += size;
        }
        offset += size;
    }
    if (cursor != label.size()) throw std::runtime_error("label exceeds switch field");
}
std::string ascii_label(const uint8_t *p, size_t size) {
    const char *digits = "0123456789abcdef";
    std::string s;
    for (size_t i=0; i<size; ++i) {
        if (p[i] < 128) s += char(p[i]);
        else { s += "\\x"; s += digits[p[i] >> 4]; s += digits[p[i] & 15]; }
    }
    return s;
}
std::string ip_text(const uint8_t *p) {
    return std::to_string(p[0])+"."+std::to_string(p[1])+"."+
           std::to_string(p[2])+"."+std::to_string(p[3]);
}
std::string shape(const std::string &s) {
    std::string out; out.reserve(s.size());
    for (char c : s) out += digit(c) ? 'd' : letter(c) ? 'a' : '-';
    return out;
}
std::string first_label(const std::string &s) {
    auto labels = split(s, true);
    return labels.empty() ? "" : lowercase(labels[0]);
}
void decrement(std::unordered_map<std::string, unsigned> &map, const std::string &s) {
    auto found = map.find(s);
    if (found == map.end()) throw std::logic_error("reference count underflow");
    if (!--found->second) map.erase(found);
    // Bound allocated bucket high-water marks as well as live map entries.
    if (map.bucket_count()>std::max<size_t>(16,4*map.size()))
        map.rehash(std::max<size_t>(1,2*map.size()));
}
}

const char *risk_name(Risk r) { return r == Risk::high ? "high" : r == Risk::medium ? "medium" : "low"; }
Mac parse_mac(const std::string &s) {
    std::string raw;
    for (char c : s) if (c != ':') raw += c;
    Bytes b = unhex(raw);
    if (b.size() != 6) throw std::runtime_error("MAC must contain six octets");
    Mac out; std::copy(b.begin(), b.end(), out.begin()); return out;
}
std::string hex(const uint8_t *p, size_t size) {
    const char *digits = "0123456789abcdef";
    std::string out; out.reserve(size*2);
    for (size_t i=0; i<size; ++i) { out += digits[p[i]>>4]; out += digits[p[i]&15]; }
    return out;
}
Bytes unhex(const std::string &s) {
    if (s.size() % 2) throw std::runtime_error("odd hexadecimal length");
    auto nibble = [](char c) -> unsigned {
        if (digit(c)) return unsigned(c-'0');
        c = lower(c);
        if (c >= 'a' && c <= 'f') return unsigned(c-'a'+10);
        throw std::runtime_error("invalid hexadecimal digit");
    };
    Bytes out; out.reserve(s.size()/2);
    for (size_t i=0; i<s.size(); i+=2) out.push_back(uint8_t((nibble(s[i])<<4) | nibble(s[i+1])));
    return out;
}
std::string json_string(const std::string &s) {
    std::string out = "\"";
    const char *digits = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c < 32 || c > 126) { out += "\\u00"; out += digits[c>>4]; out += digits[c&15]; }
        else out += char(c);
    }
    return out + '"';
}
Hashes switch_hashes(const std::string &name) {
    std::string raw = name;
    if (!raw.empty() && raw.back() == '.') raw.pop_back();
    auto labels = raw.empty() ? std::vector<std::string>{} : split(raw, false);
    for (const auto &s : labels) {
        if (s.empty() || s.size() > 63) throw std::runtime_error("invalid switch hash label");
        for (unsigned char c : s) if (c >= 128) throw std::runtime_error("non-ASCII switch hash label");
    }
    std::string first = labels.empty() ? "" : labels[0];
    std::string second = labels.size() > 1 ? labels[1] : "";
    std::string third = labels.size() > 2 ? labels[2] : "";
    Bytes sub(31, 0), zone(38, 0);
    field(sub, first.substr(0,31), 16, 0);
    if (first.size() <= 31 && second.size() <= 31) {
        field(zone, second, 16, 0);
        if (third.size() <= 7) field(zone, third, 4, 31);
    }
    return {crc16(zone), crc16(sub), first.size()>31 || second.size()>31 || third.size()>7 || labels.size()>3};
}
Observation decode_wtq(const uint8_t *f, size_t size) {
    auto reject = [](const char *s) -> void { throw std::runtime_error(s); };
    if (size < 76 || be16(f+12) != 0x88b9) reject("not a complete WTQ1 service frame");
    if (std::memcmp(f+14, "WTQ1\x01\x08", 6) || f[20] > 2 || (f[21] & ~1))
        reject("invalid WTQ1 service header");
    const size_t inner=22, ip=inner+14;
    if (be16(f+inner+12) != 0x0800 || (f[ip]>>4) != 4) reject("inner frame is not IPv4");
    const size_t ihl=(f[ip]&15)*4, total=be16(f+ip+2);
    if (ihl<20 || total<ihl+20 || total>size-ip) reject("invalid or truncated IPv4 packet");
    if (f[ip+9] != 17 || (be16(f+ip+6)&0x3fff)) reject("non-UDP or fragmented IPv4 packet");
    const size_t udp=ip+ihl, udp_len=be16(f+udp+4);
    if ((be16(f+udp)!=53 && be16(f+udp+2)!=53) || udp_len<20 || udp_len>ip+total-udp)
        reject("invalid UDP DNS datagram");
    const uint8_t *message=f+udp+8;
    const size_t message_size=udp_len-8;
    const uint16_t flags=be16(message+2);
    if (!be16(message+4) || (flags&0x8000)) reject("WTQ1 must contain a DNS question query");
    size_t cursor=12, after=std::numeric_limits<size_t>::max(), wire_length=1;
    std::array<size_t,128> visited{};
    std::string name;
    bool finished=false;
    unsigned labels=0;
    for (size_t step=0; step<visited.size(); ++step) {
        if (cursor>=message_size) reject("DNS name runs past message");
        for (size_t n=0; n<step; ++n) if (visited[n]==cursor) reject("DNS compression pointer loop");
        visited[step]=cursor;
        uint8_t length=message[cursor];
        if ((length&0xc0)==0xc0) {
            if (cursor+1>=message_size) reject("truncated DNS compression pointer");
            if (after==std::numeric_limits<size_t>::max()) after=cursor+2;
            cursor=((length&0x3f)<<8)|message[cursor+1];
            continue;
        }
        if (length&0xc0) reject("unsupported DNS label encoding");
        ++cursor;
        if (!length) {
            if (after==std::numeric_limits<size_t>::max()) after=cursor;
            finished=true; break;
        }
        if (length>message_size-cursor) reject("truncated DNS label");
        wire_length+=length+1;
        if (wire_length>255) reject("DNS name exceeds 255 wire bytes");
        if (labels++) name += '.';
        name+=ascii_label(message+cursor,length);
        cursor+=length;
    }
    if (!finished || after>message_size || message_size-after<4) reject("invalid DNS question");
    Hashes h=switch_hashes(name);
    return {name, ip_text(f+ip+12), be16(message), be16(message+after),
            h.zone, h.subdomain, f[20], bool(f[21]&1)};
}
void rewrite_return(uint8_t *f, size_t size, const Mac &dst, const Mac &src) {
    if (size<76) throw std::runtime_error("short return source frame");
    std::copy(dst.begin(),dst.end(),f);
    std::copy(src.begin(),src.end(),f+6);
    f[12]=0x88; f[13]=0xb8;
    const uint8_t header[]={'W','T','R','1',1,8,1,0};
    std::copy(std::begin(header),std::end(header),f+14);
}
Bytes make_return(const uint8_t *f, size_t size, const Mac &dst, const Mac &src) {
    Bytes out(f,f+size);
    rewrite_return(out.data(),out.size(),dst,src);
    return out;
}
Bytes make_heartbeat(const Mac &dst, const Mac &src) {
    Bytes out(60,0); outer(out,dst,src,0x88ba);
    const uint8_t header[]={'W','T','H','1',1,8,1,0};
    std::copy(std::begin(header),std::end(header),out.begin()+14); return out;
}
bool eligible_zone(const std::string &s) {
    auto labels=split(s,false);
    if (labels.size()!=2) return false;
    for (size_t i=0;i<2;++i) {
        const auto &l=labels[i];
        if (l.empty() || l.size()>(i ? 7u : 31u)) return false;
        auto alnum=[](char c) { return (c>='a'&&c<='z') || digit(c); };
        if (!alnum(l.front()) || !alnum(l.back())) return false;
        for (char c:l) if (!alnum(c) && c!='-') return false;
    }
    return true;
}
Bytes encode_policy(const Mac &dst,const Mac &src,uint8_t op,uint64_t session,
                    uint64_t seq,const std::string &zone,uint32_t ttl,uint64_t epoch) {
    if (!session || !seq) throw std::runtime_error("invalid policy session/sequence");
    if (op==1) { if (!zone.empty() || ttl) throw std::runtime_error("invalid HELLO"); }
    else if (op==2 || op==3) {
        if (!eligible_zone(zone) || (op==2 && (ttl<1000 || ttl>10000)) || (op==3 && ttl))
            throw std::runtime_error("invalid policy zone/lease");
    } else throw std::runtime_error("invalid policy operation");
    Bytes out(std::max<size_t>(60,51+zone.size()),0);
    outer(out,dst,src,0x88bb);
    std::copy_n("WTI1",4,out.begin()+14);
    out[18]=1; out[19]=37; out[20]=op;
    put64(out,22,session); put64(out,30,seq); put32(out,38,ttl); put64(out,42,epoch);
    out[50]=uint8_t(zone.size()); std::copy(zone.begin(),zone.end(),out.begin()+51);
    return out;
}
std::pair<std::string,std::string> registrable_zone(const std::string &name) {
    auto labels=split(lowercase(trim_dots(name)),true);
    if (labels.empty()) return {"",""};
    size_t suffix_size=1;
    if (labels.size()>=2 && suffixes.count(join(labels,labels.size()-2,labels.size()))) suffix_size=2;
    size_t zone_size=std::min(labels.size(),suffix_size+1), begin=labels.size()-zone_size;
    return {join(labels,begin,labels.size()),join(labels,0,begin)};
}
void Config::validate() const {
    if (experimental_distributed && sustained_completed_buckets!=2) throw std::runtime_error("B2 build accepts only the fixed two-completed-bucket branch");
    if (bucket_count>12 || max_zones>1024 || max_subdomains>4096 || max_clients>1024)
        throw std::runtime_error("native_v2 caps may be lowered for offline checks, never raised");
    if (!bucket_count || !max_zones || !max_subdomains || !max_clients || !eval_every ||
        !min_samples || !attack_evals || !clear_evals || !min_distinct ||
        !std::isfinite(bucket_seconds) || bucket_seconds<=0 || !std::isfinite(zone_ttl) || zone_ttl<=0 ||
        !std::isfinite(min_unique_fraction) || min_unique_fraction<=0 || min_unique_fraction>1)
        throw std::runtime_error("invalid detector configuration");
}
Runtime::Runtime(Config c):config_(c),last_sweep_(-std::numeric_limits<double>::infinity()) { config_.validate(); }
void Runtime::discard(const std::string &name) {
    auto it=zones_.find(name);
    if (it!=zones_.end()) {
        auto &z=*it->second.zone;
        while (!z.observations.empty()) { remove_oldest(z); ++capacity_.discarded; }
        lru_.erase(it->second.lru); zones_.erase(it);
    }
}
void Runtime::add_sub(Zone &z,const std::string &s) {
    if (s.empty()) return;
    z.ordered_subs.insert(s); ++z.shapes[shape(s)];
    z.length_sum+=s.size(); z.length_squared_sum+=s.size()*s.size();
    std::string first=first_label(s); if (!first.empty()) ++z.first_labels[first];
    std::string stem=strip_index(first); if (!stem.empty()) ++z.stems[stem];
}
void Runtime::remove_sub(Zone &z,const std::string &s) {
    if (s.empty()) return;
    z.ordered_subs.erase(s); decrement(z.shapes,shape(s));
    z.length_sum-=s.size(); z.length_squared_sum-=s.size()*s.size();
    std::string first=first_label(s); if (!first.empty()) decrement(z.first_labels,first);
    std::string stem=strip_index(first); if (!stem.empty()) decrement(z.stems,stem);
}
void Runtime::remove_oldest(Zone &z) {
    if (z.observations.empty() || z.buckets.empty()) throw std::logic_error("empty observation eviction");
    auto item=z.observations.front();
    const auto &o=*item;
    Bucket &b=z.buckets.front();
    if (b.slot!=o.slot || !b.queries || !z.queries) throw std::logic_error("observation bucket mismatch");
    decrement(b.subs,*o.sub); decrement(b.clients,*o.client);
    auto sub=z.sub_refs.find(*o.sub);
    if (sub==z.sub_refs.end()) throw std::logic_error("subdomain ref missing");
    if (sub->second==1) remove_sub(z,*o.sub);
    // Keys are not dereferenced after their final occurrence is erased.
    decrement(z.sub_refs,*o.sub); decrement(z.client_refs,*o.client);
    if (o.novel_at_admission) { if (!b.novel_queries) throw std::logic_error("novelty underflow"); --b.novel_queries; }
    --b.queries; --z.queries;
    z.observations.pop_front(); history_.erase(item);
    if (!b.queries) z.buckets.pop_front();
}
void Runtime::expire(Zone &z,int64_t slot) {
    while (!z.observations.empty() && z.observations.front()->slot<=slot-int64_t(config_.bucket_count)) {
        remove_oldest(z); ++capacity_.expired;
    }
}
void Runtime::sweep(double now) {
    clock_now_ = now;
    if (!std::isfinite(now)) throw std::runtime_error("invalid time");
    if (now-last_sweep_<config_.bucket_seconds) return;
    if (sweep_audit_) sweep_audit_(now);
    last_sweep_=now;
    for (auto it=lru_.begin();it!=lru_.end();) {
        std::string name=*it++;
        auto &z=*zones_.at(name).zone;
        if (now-z.last_seen>=config_.zone_ttl) discard(name);
        else expire(z,int64_t(std::floor(now/config_.bucket_seconds)));
    }
}
Verdict Runtime::original_confirm(const Zone &z) const {
    if (suffix_match(z.name,reserved) || suffix_match(z.name,allowlist)) return Verdict::cleared;
    const uint64_t n=z.ordered_subs.size();
    if (n<config_.min_distinct || double(n)/std::max<size_t>(1,z.client_refs.size())<2.0 ||
        double(n)/std::max<uint64_t>(1,z.queries)<config_.min_unique_fraction) return Verdict::cleared;
    // numeric_family() counts nonempty subdomain members, but the denominator
    // is the number of unique first labels. Stems may be empty and are excluded.
    if (n>=4 && !z.stems.empty() &&
        1.0-double(z.stems.size())/std::max<size_t>(1,z.first_labels.size())>=.35) return Verdict::cleared;
    if (n<3) return Verdict::attack;
    const auto &first=*z.ordered_subs.begin(), &last=*z.ordered_subs.rbegin();
    size_t prefix=0;
    while (prefix<first.size() && prefix<last.size() && first[prefix]==last[prefix]) ++prefix;
    const double mean=double(z.length_sum)/n;
    unsigned maximum_shape=0;
    for (const auto &item:z.shapes) maximum_shape=std::max(maximum_shape,item.second);
    const double agreement=double(maximum_shape)/n;
    // Exact integer moments avoid cancellation around the 0.5 boundary.
    const long double numerator=static_cast<long double>(n)*z.length_squared_sum-
                               static_cast<long double>(z.length_sum)*z.length_sum;
    const bool narrow=numerator<=.25L*static_cast<long double>(n)*n;
    if (double(prefix)/std::max(mean,1.0)>=.25 || (narrow && agreement>=.8) || agreement>=.9)
        return Verdict::cleared;
    return Verdict::attack;
}
Verdict Runtime::uncliented_confirm(const Zone &z) const {
    if (suffix_match(z.name,reserved) || suffix_match(z.name,allowlist)) return Verdict::cleared;
    const uint64_t n=z.ordered_subs.size();
    if (n<config_.min_distinct || 
        double(n)/std::max<uint64_t>(1,z.queries)<config_.min_unique_fraction) return Verdict::cleared;
    // numeric_family() counts nonempty subdomain members, but the denominator
    // is the number of unique first labels. Stems may be empty and are excluded.
    if (n>=4 && !z.stems.empty() &&
        1.0-double(z.stems.size())/std::max<size_t>(1,z.first_labels.size())>=.35) return Verdict::cleared;
    if (n<3) return Verdict::attack;
    const auto &first=*z.ordered_subs.begin(), &last=*z.ordered_subs.rbegin();
    size_t prefix=0;
    while (prefix<first.size() && prefix<last.size() && first[prefix]==last[prefix]) ++prefix;
    const double mean=double(z.length_sum)/n;
    unsigned maximum_shape=0;
    for (const auto &item:z.shapes) maximum_shape=std::max(maximum_shape,item.second);
    const double agreement=double(maximum_shape)/n;
    // Exact integer moments avoid cancellation around the 0.5 boundary.
    const long double numerator=static_cast<long double>(n)*z.length_squared_sum-
                               static_cast<long double>(z.length_sum)*z.length_sum;
    const bool narrow=numerator<=.25L*static_cast<long double>(n)*n;
    if (double(prefix)/std::max(mean,1.0)>=.25 || (narrow && agreement>=.8) || agreement>=.9)
        return Verdict::cleared;
    return Verdict::attack;
}
bool Runtime::sustained_activity(const Zone &z) const {
    if (config_.sustained_completed_buckets!=2 && config_.sustained_completed_buckets!=3)
        throw std::logic_error("unpredeclared sustained bucket count");
    const int64_t current=int64_t(std::floor(clock_now_/config_.bucket_seconds));
    for (unsigned back=1; back<=config_.sustained_completed_buckets; ++back) {
        const Bucket *found=nullptr;
        for (const auto &bucket:z.buckets) if (bucket.slot==current-int64_t(back)) { found=&bucket; break; }
        if (!found || found->novel_queries<config_.min_distinct ||
            double(found->novel_queries)/std::max<uint64_t>(1,found->queries)<config_.min_unique_fraction)
            return false;
    }
    return true;
}
bool Runtime::collection_evidence(const std::string &name) const {
    auto it=zones_.find(name);return it!=zones_.end() && uncliented_confirm(*it->second.zone)==Verdict::attack;
}
bool Runtime::original_evidence(const std::string &name) const {
    auto it=zones_.find(name);return it!=zones_.end() && original_confirm(*it->second.zone)==Verdict::attack;
}
bool Runtime::distributed_evidence(const std::string &name) const {
    auto it=zones_.find(name);return config_.experimental_distributed && it!=zones_.end() &&
        uncliented_confirm(*it->second.zone)==Verdict::attack && sustained_activity(*it->second.zone);
}
Verdict Runtime::confirm(const Zone &z) const {
                                                                                           
    // The observations deque contains only currently retained evidence; eviction and
    // expiration remove observations from retained history.
    if (uncliented_confirm(z)!=Verdict::attack) return Verdict::cleared;
    const auto surplus_activity = [&z]() {
      const size_t minimum=128;
      if(z.observations.size()<minimum)return false;
      int score=0;for(size_t i=z.observations.size()-std::min<size_t>(512,z.observations.size());i<z.observations.size();++i)score+=z.observations[i]->novel_at_admission?1:-9;
      return score>=int(minimum);
    };
    return surplus_activity()?Verdict::attack:Verdict::cleared;
}
void Runtime::evaluate(Zone &z) {
    if (z.queries<config_.min_samples && !suffix_match(z.name,reserved) && !suffix_match(z.name,allowlist)) return;
    if (confirm(z)==Verdict::attack) {
        ++z.attack_streak; z.clear_streak=0;
        z.risk=z.attack_streak>=config_.attack_evals ? Risk::high : Risk::medium;
    } else {
        ++z.clear_streak; z.attack_streak=0;
        if (z.clear_streak>=config_.clear_evals) z.risk=Risk::low;
    }
}
bool Runtime::observe(const Observation &p,double now) {
    // decode_wtq already bounds the DNS wire expansion and emits IPv4 clients.
    // Keep direct core callers from bypassing the fixed string-memory bound.
    if (p.qname.size()>Config::max_decoded_name_bytes || p.client.size()>Config::max_client_bytes)
        throw std::runtime_error("observation exceeds fixed native_v2 string bound");
    size_t label_bytes=0;
    for (char c:p.qname) {
        if (c=='.') label_bytes=0;
        else if (++label_bytes>63) throw std::runtime_error("observation exceeds DNS label bound");
    }
    sweep(now);
    auto names=registrable_zone(p.qname);
    if (names.first.empty()) return false;
    auto found=zones_.find(names.first);
    if (found==zones_.end()) {
        if (zones_.size()==config_.max_zones) discard(lru_.front());
        lru_.push_back(names.first);
        auto z=std::make_unique<Zone>(); z->name=names.first; z->last_seen=now;
        Entry e{std::move(z),std::prev(lru_.end())};
        found=zones_.emplace(names.first,std::move(e)).first;
    } else {
        lru_.splice(lru_.end(),lru_,found->second.lru);
        found->second.zone->last_seen=now;
    }
    Zone &z=*found->second.zone;
    const int64_t slot=int64_t(std::floor(now/config_.bucket_seconds));
    expire(z,slot);
    // Remove complete oldest observations, never incomplete evidence counters.
    while (z.observations.size()>=Config::observations_per_zone) {
        remove_oldest(z); ++capacity_.zone_budget_evicted;
    }
    while (!z.sub_refs.count(names.second) && z.sub_refs.size()>=config_.max_subdomains) {
        remove_oldest(z); ++capacity_.name_evicted;
    }
    while (!z.client_refs.count(p.client) && z.client_refs.size()>=config_.max_clients) {
        remove_oldest(z); ++capacity_.client_evicted;
    }
    while (history_.size()>=Config::observations_global) {
        remove_oldest(*history_.front().zone); ++capacity_.global_budget_evicted;
    }
    const bool novel = !names.second.empty() && !z.sub_refs.count(names.second);
    if (z.buckets.empty() || z.buckets.back().slot!=slot) { Bucket b; b.slot=slot; z.buckets.push_back(std::move(b)); }
    Bucket &b=z.buckets.back();
    ++b.queries; ++z.queries; ++z.total_queries; ++z.samples;
    if (novel) {
        if (z.novel_admissions==std::numeric_limits<uint64_t>::max()) throw std::logic_error("novelty sequence exhausted");
        ++b.novel_queries; ++z.novel_admissions;
    }
    auto track=[&z](const std::string &value,auto &refs,auto &values,bool sub) -> const std::string * {
        ++values[value];
        auto item=refs.find(value);
        if (item==refs.end()) {
            item=refs.emplace(value,1).first;
            if (sub) add_sub(z,value);
        } else ++item->second;
        return &item->first;
    };
    auto sub=track(names.second,z.sub_refs,b.subs,true);
    auto client=track(p.client,z.client_refs,b.clients,false);
    history_.push_back({&z,slot,++capacity_.admitted,sub,client,novel});
    z.observations.push_back(std::prev(history_.end()));
    capacity_.peak_retained=std::max<uint64_t>(capacity_.peak_retained,history_.size());
    if (z.samples%config_.eval_every==0) evaluate(z);
    return z.risk==Risk::high && confirm(z)==Verdict::attack;
}
bool Runtime::confirmed(const std::string &name) const {
    auto found=zones_.find(name);
    return found!=zones_.end() && found->second.zone->risk==Risk::high && confirm(*found->second.zone)==Verdict::attack;
}
View Runtime::view(const std::string &name) const {
    auto found=zones_.find(name);
    if (found==zones_.end()) return {};
    const Zone &z=*found->second.zone;
    return {true,z.truncated,z.risk,z.sub_refs.size(),z.client_refs.size(),z.queries,z.samples,z.novel_admissions};
}
std::string Runtime::capacity_json() const {
    std::ostringstream out;
    out<<"{\"event\":\"native_capacity\",\"version\":2,\"observations_per_zone\":"
       <<Config::observations_per_zone<<",\"observations_global\":"<<Config::observations_global
       <<",\"retained\":"<<history_.size()<<",\"peak_retained\":"<<capacity_.peak_retained
       <<",\"admitted\":"<<capacity_.admitted<<",\"name_evicted\":"<<capacity_.name_evicted
       <<",\"client_evicted\":"<<capacity_.client_evicted<<",\"zone_budget_evicted\":"<<capacity_.zone_budget_evicted
       <<",\"global_budget_evicted\":"<<capacity_.global_budget_evicted
       <<",\"expired\":"<<capacity_.expired<<",\"discarded\":"<<capacity_.discarded<<"}";
    return out.str();
}
std::string Runtime::debug_json() const {
    std::ostringstream out;
    auto map_json=[&out](const auto &m) {
        std::vector<std::pair<std::string,uint64_t>> values;
        for (const auto &v:m) values.emplace_back(v.first,v.second);
        std::sort(values.begin(),values.end()); out<<'{';
        bool first=true;
        for (const auto &v:values) { if (!first) out<<','; first=false; out<<json_string(v.first)<<':'<<v.second; }
        out<<'}';
    };
    out<<"{\"capacity\":"<<capacity_json()<<",\"lru\":[";
    bool first=true;
    for (const auto &name:lru_) { if (!first) out<<','; first=false; out<<json_string(name); }
    out<<"],\"global_observations\":["; first=true;
    for (const auto &o:history_) {
        if (!first) out<<',';
        first=false;
        out<<"{\"sequence\":"<<o.sequence<<",\"zone\":"<<json_string(o.zone->name)
           <<",\"slot\":"<<o.slot<<",\"sub\":"<<json_string(*o.sub)<<",\"client\":"<<json_string(*o.client)<<",\"novel_at_admission\":"<<o.novel_at_admission<<'}';
    }
    out<<"],\"zones\":{"; first=true;
    for (const auto &name:lru_) {
        if (!first) out<<',';
        first=false;
        const auto &z=*zones_.at(name).zone;
        out<<json_string(name)<<":{\"risk\":"<<json_string(risk_name(z.risk))
           <<",\"attack_streak\":"<<z.attack_streak<<",\"clear_streak\":"<<z.clear_streak
           <<",\"queries\":"<<z.queries<<",\"novel_admissions\":"<<z.novel_admissions<<",\"samples\":"<<z.samples
           <<",\"total_queries\":"<<z.total_queries<<",\"length_sum\":"<<z.length_sum
           <<",\"length_squared_sum\":"<<z.length_squared_sum<<",\"sub_refs\":";
        map_json(z.sub_refs); out<<",\"client_refs\":"; map_json(z.client_refs);
        out<<",\"shapes\":"; map_json(z.shapes); out<<",\"first_labels\":"; map_json(z.first_labels);
        out<<",\"stems\":"; map_json(z.stems); out<<",\"ordered_subs\":[";
        bool inner_first=true;
        for (const auto &s:z.ordered_subs) { if (!inner_first) out<<','; inner_first=false; out<<json_string(s); }
        out<<"],\"buckets\":["; inner_first=true;
        for (const auto &b:z.buckets) {
            if (!inner_first) out<<',';
            inner_first=false;
            out<<"{\"slot\":"<<b.slot<<",\"queries\":"<<b.queries<<",\"novel_queries\":"<<b.novel_queries<<",\"subs\":";
            map_json(b.subs); out<<",\"clients\":"; map_json(b.clients); out<<'}';
        }
        out<<"]}";
    }
    out<<"}}"; return out.str();
}

Policies::Policies(Runtime &r,Mac dst,Mac src,uint64_t session,Send callback,unsigned renew,unsigned ttl):
    runtime_(r),dst_(dst),src_(src),session_(session),send_(std::move(callback)),
    renew_ms_(renew),ttl_ms_(ttl),next_tick_(-std::numeric_limits<double>::infinity()) {
    if (!session || renew<200 || renew>2000 || ttl<1000 || ttl<3*renew || ttl>10000)
        throw std::runtime_error("invalid policy configuration");
}
void Policies::send(uint8_t op,const std::string &zone,unsigned ttl,uint64_t epoch) {
    if (sequence_==std::numeric_limits<uint64_t>::max()) throw std::runtime_error("policy sequence exhausted");
    auto frame=encode_policy(dst_,src_,op,session_,++sequence_,zone,ttl,epoch);
    send_(op,zone,frame);
}
void Policies::forget(const std::string &zone) {
    auto it=known_index_.find(zone);
    if (it!=known_index_.end()) { known_.erase(it->second); known_index_.erase(it); }
}
void Policies::observe_zone(const std::string &zone,uint64_t epoch) {
    if (!eligible_zone(zone)) return;
    if (runtime_.confirmed(zone)) {
        if (!known_index_.count(zone)) {
            if (known_.size()>=256) return;
            known_.push_back(zone); known_index_[zone]=std::prev(known_.end());
        }
        if (!active_.count(zone)) { send(2,zone,ttl_ms_,epoch); active_.insert(zone); }
    } else if (active_.count(zone)) { send(3,zone,0,epoch); active_.erase(zone); forget(zone); }
}
void Policies::tick(double now,uint64_t epoch) {
    if (now<next_tick_) return;
    next_tick_=now+renew_ms_/1000.0;
    runtime_.sweep(now); send(1,"",0,epoch);
    for (auto it=known_.begin();it!=known_.end();) {
        std::string zone=*it++;
        if (runtime_.confirmed(zone)) { send(2,zone,ttl_ms_,epoch); active_.insert(zone); }
        else {
            if (active_.count(zone)) { send(3,zone,0,epoch); active_.erase(zone); }
            forget(zone);
        }
    }
}
void Policies::close(uint64_t epoch) {
    std::vector<std::string> names(active_.begin(),active_.end()); std::sort(names.begin(),names.end());
    for (const auto &zone:names) send(3,zone,0,epoch);
    active_.clear();
}
}
