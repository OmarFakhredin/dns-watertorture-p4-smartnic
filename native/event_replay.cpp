#include "core.hpp"
#include <iostream>
#include <sstream>
#include <string>
int main(int argc,char **argv){try{dns::Config c;c.experimental_distributed=true;c.sustained_completed_buckets=2;
#ifndef ORIGINAL_SOURCE
c.offline_candidate=argc>1?argv[1]:"baselineB2";
#endif
dns::Runtime r(c);std::string line;
 std::cout<<"ordinal,denied,distinct,clients,queries,risk,confirmed,original_predicate,distributed_predicate\n";
 while(std::getline(std::cin,line)){std::istringstream s(line);char kind;double at;s>>kind>>at;if(kind=='S'){r.sweep(at);continue;}if(kind!='Q')throw std::runtime_error("unknown native event");uint64_t ordinal;std::string hex;unsigned id,type,z,sub,tier,overflow;dns::Observation p;if(!(s>>ordinal>>hex>>p.client>>id>>type>>z>>sub>>tier>>overflow))throw std::runtime_error("bad native event");auto name=dns::unhex(hex);p.qname.assign(name.begin(),name.end());p.dns_id=id;p.qtype=type;p.zone_hash=z;p.subdomain_hash=sub;p.tier=tier;p.overflow=overflow;bool denied=r.observe(p,at);auto zone=dns::registrable_zone(p.qname).first;auto v=r.view(zone);std::cout<<ordinal<<','<<denied<<','<<v.distinct<<','<<v.clients<<','<<v.queries<<','<<dns::risk_name(v.risk)<<','<<r.confirmed(zone)<<','<<r.original_evidence(zone)<<','<<r.distributed_evidence(zone)<<'\n';}
 return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
