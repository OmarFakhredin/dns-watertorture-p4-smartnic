#include "core.hpp"
#include <iostream>
#include <stdexcept>
#include <tuple>
#define REQUIRE(x) do { if(!(x)) throw std::runtime_error(#x); } while(0)
static std::string letters(uint64_t n) {
    std::string s;int length=8+n%13;
    for(int i=0;i<length;++i){n=n*6364136223846793005ULL+1442695040888963407ULL;s+="abcdefghijklmnopqrstuvwxyz0123456789"[(n>>32)%36];}
    return s;
}
static dns::Config configuration() {
    dns::Config c;c.experimental_distributed=true;
#ifdef SEALED_CANDIDATE
    c.offline_candidate="surplus128";
#endif
    return c;
}
static dns::Observation packet(unsigned i) {
    dns::Observation p;p.qname=letters(i)+".fixturezone.net";p.client="10.9.0.1";p.qtype=1;return p;
}
int main() { try {
    dns::Mac a{},b{};
    {
        dns::Runtime r(configuration());std::vector<unsigned> events;
        dns::Policies policies(r,a,b,123,[&](uint8_t op,const std::string&,const dns::Bytes& f){REQUIRE(!f.empty());events.push_back(op);},1000,5000);
        for(unsigned i=0;i<144;++i){bool denied=r.observe(packet(i),i*.05);
            if(i==79){REQUIRE(r.original_evidence("fixturezone.net"));REQUIRE(!denied);}
            REQUIRE(denied==(i==143));policies.observe_zone("fixturezone.net",uint64_t(i*.05*1e9));}
        REQUIRE(policies.active_count()==1);
        REQUIRE(r.observe(packet(0),7.2)); // 144 novel - one repeat: 135.
        REQUIRE(!r.observe(packet(0),7.25)); // 144 novel - two repeats: 126.
        REQUIRE(r.original_evidence("fixturezone.net"));
        REQUIRE(r.view("fixturezone.net").risk==dns::Risk::high);
        REQUIRE(!r.confirmed("fixturezone.net")); // Current evidence beats retained high risk.
        policies.observe_zone("fixturezone.net",7250000000ULL);
        REQUIRE(policies.active_count()==0 && events.back()==3);
        std::cout<<"PASS_MIN128_NO_LEGACY_OR_CURRENT_CLEAR_POLICY_REMOVE\n";
    }
    {
        dns::Runtime r(configuration());
        for(unsigned i=0;i<600;++i)r.observe(packet(i),i*.01);
        REQUIRE(r.confirmed("fixturezone.net"));
        for(unsigned i=0;i<38;++i)REQUIRE(r.observe(packet(0),6+i*.01));
        // Only latest 512 count: 473 novel and 39 repeats => 122, though
        // all-history score would be 249. This catches an unbounded score.
        REQUIRE(!r.observe(packet(0),6.38));
        REQUIRE(r.original_evidence("fixturezone.net"));
        REQUIRE(r.view("fixturezone.net").risk==dns::Risk::high);
        std::cout<<"PASS_LATEST512_SCORE_AND_CURRENT_DENIAL\n";
    }
    {
        dns::Runtime r(configuration());std::vector<unsigned> events;
        dns::Policies policies(r,a,b,124,[&](uint8_t op,const std::string&,const dns::Bytes&){events.push_back(op);},1000,5000);
        for(unsigned i=0;i<700;++i){r.observe(packet(i),i*.05);policies.observe_zone("fixturezone.net",uint64_t(i*.05*1e9));policies.tick(i*.05,uint64_t(i*.05*1e9));}
        REQUIRE(r.confirmed("fixturezone.net") && policies.active_count()==1);
        policies.tick(80,80000000000ULL);
        REQUIRE(r.confirmed("fixturezone.net") && policies.active_count()==1);
        policies.tick(160,160000000000ULL);
        REQUIRE(!r.confirmed("fixturezone.net") && r.retained_count()==0 && policies.active_count()==0);
        REQUIRE(events.back()==3 && r.view("fixturezone.net").risk==dns::Risk::high);
        REQUIRE(!r.observe(packet(800),160.05));
        policies.close(161000000000ULL);policies.tick(800,800000000000ULL);
        REQUIRE(r.zone_count()==0 && r.retained_count()==0);
        std::cout<<"PASS_RETAINED_EXPIRY_POLICY_DELETE_CLOSE_IDLE_TTL\n";
    }
    return 0;
} catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;} }
