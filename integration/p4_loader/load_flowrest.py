
                                                                         
import os as _release_os
if _release_os.environ.get('DNS_RESEARCH_ENABLE_SITE_TOOLS') != 'I_HAVE_REVIEWED_SITE_CONFIGURATION':
    raise RuntimeError('Site tools are inactive. See docs/MODEL_BLUEFIELD.md and site.example.json.')
import argparse, hashlib, json, os, pathlib, sys, time
sys.path[:0]=['/SITE_HOME/open-p4studio/install/lib/python3.8/site-packages/tofino','/SITE_HOME/open-p4studio/install/lib/python3.8/site-packages']

def load(info, target, gc, path, rule):
    tables=json.loads(path.read_text());assert tables['model_sha256']=='24027905ccd718b7544cc7e06022aff2bb86aef60129e6f09f36d6274188a745'
    expected={};actual={}
    def install(name,rows):
        table=info.table_get('SwitchIngress.'+name);table.entry_del(target);keys=[];data=[]
        for key_specs,data_specs,action in rows:
            keys.append(table.make_key([gc.KeyTuple(**k) for k in key_specs]));data.append(table.make_data([gc.DataTuple(n,v) for n,v in data_specs],'SwitchIngress.'+action))
        table.entry_add(target,keys,data)
        exp=sorted([{'key':k.to_dict(),'data':d.to_dict()} for k,d in zip(keys,data)],key=lambda x:json.dumps(x,sort_keys=True))
        got=sorted([{'key':k.to_dict(),'data':d.to_dict()} for d,k in table.entry_get(target,None,{'from_hw':True})],key=lambda x:json.dumps(x,sort_keys=True))
        assert got==exp,(name,'Readback differs');expected[name]=exp;actual[name]=got
    for e in tables['encoders']:
        f=e['feature'];shift=5 if f==0 else 0;rows=[]
        for priority,r in enumerate(e['rows'],1):
            rows.append(([{'name':'ig_md.'+e['name'],'low':r['low'],'high':r['high']},{'name':'$MATCH_PRIORITY','value':priority}],[(('c%d'%i),v>>shift) for i,v in enumerate(r['codes'])],'rf_encode_%d'%f))
        install('rf_encoder_%d'%f,rows)
    for t in tables['trees']:
        i=t['id'];rows=[]
        for priority,l in enumerate(t['leaves'],1):
            rows.append(([{'name':'ig_md.rf_zone%d'%i,'value':l['value']>>5,'mask':l['mask']>>5},{'name':'ig_md.rf_distinct%d'%i,'value':l['value']&31,'mask':l['mask']&31},{'name':'$MATCH_PRIORITY','value':priority}],[('leaf',l['id'])],'rf_leaf_%d'%i))
        install('rf_tree_%d'%i,rows)
    rows=[]
    for r in tables['aggregation']:
        score=r[rule+'_score'];assert score in [0,8]
        rows.append(([{'name':'ig_md.rf_leaf%d'%i,'value':v} for i,v in enumerate(r['leaves'])],[('score',score)],'set_score'))
    install('rf_aggregation',rows)
    tiers=info.table_get('SwitchIngress.score_to_tier');field=next(f for f in tiers.info.key_field_name_list_get() if f!='$MATCH_PRIORITY');rows=[]
    for priority,(lo,hi,tier) in enumerate([(3,5,1),(6,255,2)],1):rows.append(([{'name':field,'low':lo,'high':hi},{'name':'$MATCH_PRIORITY','value':priority}],[('tier',tier)],'set_tier'))
    install('score_to_tier',rows)
    return {'status':'PASS_EXACT_READBACK','rule':rule,'tables':actual,'table_file_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'epoch_ns':time.time_ns()}

def main():
    p=argparse.ArgumentParser();p.add_argument('--runtime',type=pathlib.Path,required=True);p.add_argument('--tables',type=pathlib.Path,required=True);p.add_argument('--rule',choices=['probability','majority'],required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();assert not a.out.exists()
    from ownership import owned_namespace
    owned_namespace(a.runtime)
    import bfrt_grpc.client as gc
    client=gc.ClientInterface(grpc_addr='localhost:50052',client_id=97,device_id=0);client.bind_pipeline_config('basic');result=load(client.bfrt_info_get('basic'),gc.Target(device_id=0,pipe_id=0xffff),gc,a.tables,a.rule)
    with a.out.open('x') as f:json.dump(result,f,indent=2)
    print(json.dumps({'status':result['status'],'rule':a.rule,'rows':{n:len(v) for n,v in result['tables'].items()}}))

if __name__=='__main__':main()
