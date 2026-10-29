import argparse, itertools, json, math, pathlib, hashlib, shutil, difflib

ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = ROOT / 'input_DNS_RF_Instructor_Package'
FEATURES = ['zone_rate_k','distinct_est_k','src_spread_k','client_zone_rate_k','nxd_count_k','bigram_k']
MODEL_SHA = '24027905ccd718b7544cc7e06022aff2bb86aef60129e6f09f36d6274188a745'

def digest(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def build(model):
    nodes = [[n for n,l in enumerate(t['children_left']) if l >= 0] for t in model['trees']]
    used = sorted({t['feature'][n] for t, ns in zip(model['trees'], nodes) for n in ns})
    assert used == [0,1]
    positions = []
    for t, ns in zip(model['trees'], nodes):
        order = [n for f in used for n in ns if t['feature'][n] == f]
        positions.append({n:len(order)-1-i for i,n in enumerate(order)})
    encoders = []
    for f in used:
        cuts = sorted({math.floor(t['threshold'][n]) for t,ns in zip(model['trees'],nodes) for n in ns if t['feature'][n] == f})
        rows = []
        for lo, hi in zip([0]+[c+1 for c in cuts],cuts+[65535]):
            codes = [sum(1 << pos[n] for n in ns if t['feature'][n] == f and lo > math.floor(t['threshold'][n])) for t,ns,pos in zip(model['trees'],nodes,positions)]
            rows.append({'low':lo,'high':hi,'codes':codes})
        encoders.append({'feature':f,'name':FEATURES[f],'rows':rows})
    trees = []
    for ti,(t, pos) in enumerate(zip(model['trees'],positions)):
        leaves=[]
        def walk(n, value, mask):
            if t['children_left'][n] < 0:
                v=t['value'][n][0]
                leaves.append({'id':len(leaves),'node':n,'value':value,'mask':mask,'attack_probability':v[1]/sum(v),'class':int(v[1]>v[0])})
            else:
                b=1<<pos[n]
                walk(t['children_left'][n],value,mask|b)
                walk(t['children_right'][n],value|b,mask|b)
        walk(0,0,0)
        trees.append({'id':ti,'width':len(pos),'zone_width':sum(t['feature'][n]==0 for n in pos),'distinct_width':sum(t['feature'][n]==1 for n in pos),'node_bit_positions':pos,'leaves':leaves})
    aggregation=[]
    for ls in itertools.product(*(t['leaves'] for t in trees)):
        prob=sum(l['attack_probability'] for l in ls)/len(trees)
        aggregation.append({'leaves':[l['id'] for l in ls],'mean_attack_probability':prob,'probability_score':8*int(prob>.5),'majority_score':8*int(sum(l['class'] for l in ls)>len(trees)//2)})
    return {'schema':'dns-flowrest-tables-v1','model_sha256':MODEL_SHA,'features':FEATURES,'used_features':used,'encoders':encoders,'trees':trees,'aggregation':aggregation,'decision':'mean normalized leaf attack probability > 0.5; ties nominal','majority_decision':'strict majority of binary argmax leaf classes; leaf ties class 0'}

def p4_block(tables):
    text=[]
    for enc in tables['encoders']:
        f=enc['feature']
        args=', '.join('bit<%d> c%d'%(t['zone_width' if f==0 else 'distinct_width'],i) for i,t in enumerate(tables['trees']))
        assignments=' '.join('ig_md.rf_%s%d = c%d;'%('zone' if f==0 else 'distinct',i,i) for i in range(3))
        text.append('    action rf_encode_%d(%s) { %s }'%(f,args,assignments))
        text.append('    table rf_encoder_%d { key = { ig_md.%s : range; } actions = { rf_encode_%d; } size = %d; const default_action = rf_encode_%d(0,0,0); }'%(f,enc['name'],f,len(enc['rows']),f))
    for i,t in enumerate(tables['trees']):
        text.append('    action rf_leaf_%d(bit<3> leaf) { ig_md.rf_leaf%d = leaf; }'%(i,i))
        text.append('    table rf_tree_%d { key = { ig_md.rf_zone%d : ternary; ig_md.rf_distinct%d : ternary; } actions = { rf_leaf_%d; } size = %d; const default_action = rf_leaf_%d(0); }'%(i,i,i,i,len(t['leaves']),i))
    text.append('    table rf_aggregation { key = { ig_md.rf_leaf0 : exact; ig_md.rf_leaf1 : exact; ig_md.rf_leaf2 : exact; } actions = { set_score; } size = 512; const default_action = set_score(0); }')
    text.append('    Register<bit<32>, bit<1>>(1, 0) rf_observation;')
    text.append('    RegisterAction<bit<32>, bit<1>, bit<32>>(rf_observation) rf_observe = { void apply(inout bit<32> v, out bit<32> r) { v = 2w0 ++ ig_md.rf_zone0 ++ ig_md.rf_distinct0 ++ ig_md.rf_zone1 ++ ig_md.rf_distinct1 ++ ig_md.rf_zone2 ++ ig_md.rf_distinct2 ++ ig_md.rf_leaf0 ++ ig_md.rf_leaf1 ++ ig_md.rf_leaf2; r = v; } };')
    return '\n'.join(text)+'\n'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=pathlib.Path,required=True);parser.add_argument('--fold-overflow',action='store_true');args=parser.parse_args()
    assert not args.out.exists()
    assert digest(SOURCE/'model/forest.json')==MODEL_SHA
    model=json.loads((SOURCE/'model/forest.json').read_text())
    tables=build(model);args.out.mkdir()
    (args.out/'flowrest_tables.json').write_text(json.dumps(tables,indent=2)+'\n')
    diffs=[]
    for mode in ['functional','measurement']:
        original=SOURCE if mode=='functional' else SOURCE/'measurement';out=args.out/mode;out.mkdir()
        for p in sorted(original.glob('*.p4')):
            before=p.read_text();after=before
            if p.name=='headers.p4':
                fields=[]
                for i,t in enumerate(tables['trees']):
                    fields.extend(['    bit<%d> rf_zone%d;'%(t['zone_width'],i),'    bit<%d> rf_distinct%d;'%(t['distinct_width'],i),'    bit<3> rf_leaf%d;'%i])
                anchor='    bit<1>  new_subdomain;';assert after.count(anchor)==1;after=after.replace(anchor,'\n'.join(fields)+'\n\n'+anchor)
            if p.name=='ingress.p4':
                start=after.index('    table score_contribution {');end=after.index('\n    }',start)+6
                after=after[:start]+p4_block(tables)+after[end:]
                assert after.count('score_contribution.apply();')==1
                after=after.replace('score_contribution.apply();','rf_encoder_0.apply();\n                rf_encoder_1.apply();\n                rf_tree_0.apply();\n                rf_tree_1.apply();\n                rf_tree_2.apply();\n                rf_aggregation.apply();\n                rf_observe.execute((bit<1>)0);')
                if args.fold_overflow:
                    action='action set_score(bit<8> score) { ig_md.suspicion_score = score; }'
                    assert after.count(action)==1
                    assert {a['probability_score'] for a in tables['aggregation']}=={0,8}
                    assert {a['majority_score'] for a in tables['aggregation']}=={0,8}
                    after=after.replace(action,'action set_score(bit<8> score) { ig_md.suspicion_score = score[7:1] ++ ig_md.overflow_flag; }')
                    import re
                    after,count=re.subn(r'if \(ig_md.overflow_flag == 1\) \{\s*ig_md.suspicion_score = ig_md.suspicion_score \+ 1;\s*\}', '', after)
                    assert count==1
            (out/p.name).write_text(after)
            if before!=after:diffs.extend(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='baseline/'+mode+'/'+p.name,tofile='flowrest/'+mode+'/'+p.name))
        assert len(list(out.glob('*.p4')))==9
    (args.out/'classifier.diff').write_text(''.join(diffs))
    (args.out/'generation_manifest.json').write_text(json.dumps({'model_sha256':MODEL_SHA,'tables_sha256':digest(args.out/'flowrest_tables.json'),'generator_sha256':digest(__file__),'sources':[{'path':str(p.relative_to(args.out)),'sha256':digest(p)} for p in sorted(args.out.rglob('*.p4'))]},indent=2))
    print(json.dumps({'encoders':[len(e['rows']) for e in tables['encoders']],'tree_widths':[t['width'] for t in tables['trees']],'leaves':[len(t['leaves']) for t in tables['trees']],'aggregation_rows':len(tables['aggregation'])}))

if __name__=='__main__':main()
