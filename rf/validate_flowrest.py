import argparse, itertools, json, pathlib, platform, warnings, hashlib, math
import numpy as np
import joblib, scipy, sklearn
from generate_flowrest import FEATURES, MODEL_SHA, digest, build

ROOT=pathlib.Path(__file__).resolve().parent
SOURCE=ROOT/'input_DNS_RF_Instructor_Package'

def reference(model, x):
    attack=[];hard=[];node_ids=[]
    for t in model['trees']:
        nodes=np.zeros(len(x),dtype=int)
        while True:
            active=np.array(t['children_left'])[nodes]>=0
            if not active.any():break
            ns=nodes[active];left=x[active,np.array(t['feature'])[ns]]<=np.array(t['threshold'])[ns]
            nodes[active]=np.where(left,np.array(t['children_left'])[ns],np.array(t['children_right'])[ns])
        v=np.array(t['value'])[nodes,0,:]
        attack.append(v[:,1]/v.sum(axis=1));hard.append(v[:,1]>v[:,0]);node_ids.append(nodes)
    p=np.array(attack).mean(axis=0)
    return p,p>.5,np.array(hard).sum(axis=0)>=2,np.array(node_ids).T

def mapped(tables,x):
    words=np.zeros((len(x),3),dtype=int)
    for encoder in tables['encoders']:
        coverage=np.zeros(len(x),dtype=int)
        for row in encoder['rows']:
            active=(x[:,encoder['feature']]>=row['low'])&(x[:,encoder['feature']]<=row['high'])
            words[active]|=np.array(row['codes']);coverage[active]+=1
        assert np.all(coverage==1)
    leaves=np.zeros_like(words);matched_nodes=np.zeros_like(words)
    for i,tree in enumerate(tables['trees']):
        coverage=np.zeros(len(x),dtype=int)
        for leaf in tree['leaves']:
            assert leaf['value']&~leaf['mask']==0 and 0<leaf['mask']<(1<<tree['width'])
            active=(words[:,i]&leaf['mask'])==leaf['value']
            leaves[active,i]=leaf['id'];matched_nodes[active,i]=leaf['node'];coverage[active]+=1
        assert np.all(coverage==1), 'Missing or ambiguous leaf'
    index=leaves[:,0]*64+leaves[:,1]*8+leaves[:,2]
    return np.array([a['probability_score'] for a in tables['aggregation']])[index]>0,np.array([a['majority_score'] for a in tables['aggregation']])[index]>0,matched_nodes

def fused(model,x):
    coverage=np.zeros(len(x),dtype=int);prediction=np.zeros(len(x),dtype=bool)
    for row in model['table_rows']:
        bounds=np.array(row['bounds']);active=((x>=bounds[:,0])&(x<=bounds[:,1])).all(axis=1)
        coverage[active]+=1;prediction[active]=row['score']>0
    assert np.all(coverage==1)
    return prediction

def metrics(y,p):
    tp=int(((y==1)&p).sum());tn=int(((y==0)&~p).sum());fp=int(((y==0)&p).sum());fn=int(((y==1)&~p).sum())
    return {'confusion_matrix_true_rows_predicted_columns':[[tn,fp],[fn,tp]],'precision':tp/(tp+fp) if tp+fp else 0.,'recall':tp/(tp+fn) if tp+fn else 0.,'false_positive_rate':fp/(fp+tn) if fp+tn else 0.,'F1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--candidate',type=pathlib.Path,default=ROOT/'candidate001');parser.add_argument('--out',type=pathlib.Path,required=True);args=parser.parse_args();assert not args.out.exists()
    assert platform.python_version()=='3.12.14'
    assert [sklearn.__version__,np.__version__,joblib.__version__,scipy.__version__]==['1.8.0','2.3.5','1.5.3','1.17.0']
    assert digest(SOURCE/'model/forest.json')==MODEL_SHA
    model=json.loads((SOURCE/'model/forest.json').read_text());tables=json.loads((args.candidate/'flowrest_tables.json').read_text());assert tables==json.loads(json.dumps(build(model)))
    fitted_path=ROOT/'input_DNS_RF_Training_and_Model_NoComments/dns_rf_candidate.joblib'
    fitted=joblib.load(fitted_path);assert fitted.get_params()==model['params'];assert fitted.classes_.tolist()==[0,1];assert fitted.feature_names_in_.tolist()==FEATURES and fitted.n_features_in_==6
    arrays=[]
    for i,(tree,expected) in enumerate(zip(fitted.estimators_,model['trees'])):
        for field in ['children_left','children_right','feature','threshold','value']:
            actual=getattr(tree.tree_,field);wanted=np.array(expected[field]);assert np.array_equal(actual,wanted),(i,field)
            arrays.append({'tree':i,'array':field,'exact_equal':True,'shape':list(actual.shape)})
    assert len(fitted.estimators_)==3
    groups=[];labelled={}
    for name in ['train','development']:
        p=SOURCE/('training/data/'+name+'_features.json');rows=json.loads(p.read_text());x=np.array([r['features'][:5]+[0] for r in rows],dtype=np.uint16);y=np.array([r['label'] for r in rows]);groups.append((name,x));labelled[name]=(y,digest(p))
    domain=[];disagreements=[]
    for a,b in itertools.product(tables['encoders'][0]['rows'],tables['encoders'][1]['rows']):
        points=set(itertools.product([a['low'],a['high'],(a['low']+a['high'])//2],[b['low'],b['high'],(b['low']+b['high'])//2]))
        for z,d in points:
            for extras in itertools.product([0,65535],repeat=4):domain.append([z,d]+list(extras))
        v=np.array([[(a['low']+a['high'])//2,(b['low']+b['high'])//2,0,0,0,0]],dtype=np.uint16);prob,pred,maj,_=reference(model,v)
        if pred[0]!=maj[0]:disagreements.append({'bounds':[[a['low'],a['high']],[b['low'],b['high']]],'mean_probability':float(prob[0]),'probability_class':int(pred[0]),'majority_class':int(maj[0])})
    groups.append(('all_domain_cells_boundaries_endpoints_unused_extremes',np.array(domain,dtype=np.uint16)))
    saved=[]
    for p in sorted((SOURCE/'validation').glob('saved_*_vectors.json')):
        data=json.loads(p.read_text());rows=data.get('events',data.get('queries'))
        assert rows is not None
        saved.extend(r['features'] for r in rows)
    groups.append(('saved_functional_and_measurement_vectors',np.array(saved,dtype=np.uint16)))
    groups.append(('deterministic_probes_seed_20261011',np.random.default_rng(20261011).integers(0,65536,size=(100000,6),dtype=np.uint16)))
    reports=[];comparison={};maxdiff=0.;total=0
    for name,x in groups:
        p,expected,majority,nodes=reference(model,x);actual,actual_majority,actual_nodes=mapped(tables,x);fused_pred=fused(model,x)
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore',message='X does not have valid feature names')
            fitted_probs=fitted.predict_proba(x)[:,1];fitted_pred=fitted.predict(x)
        checks={'flowrest_probability_mismatches':int((actual!=expected).sum()),'flowrest_majority_mismatches':int((actual_majority!=majority).sum()),'leaf_node_mismatches':int((actual_nodes!=nodes).sum()),'fused_mismatches':int((fused_pred!=expected).sum()),'fitted_decision_mismatches':int((fitted_pred!=expected).sum())}
        assert not any(checks.values()),(name,checks)
        diff=float(np.max(np.abs(p-fitted_probs)));maxdiff=max(maxdiff,diff);total+=len(x)
        reports.append({'group':name,'count':len(x),**checks,'fitted_probability_max_absolute_difference':diff,'majority_vs_probability_disagreements':int((majority!=expected).sum()),'identity_sha256_uint16_little_endian':hashlib.sha256(x.astype('<u2').tobytes()).hexdigest()})
        if name in labelled:
            y,sha=labelled[name];comparison[name]={'rows':len(x),'input_sha256':sha,'probability':metrics(y,expected),'majority':metrics(y,majority),'disagreements':int((majority!=expected).sum())}
    for row in tables['aggregation']:
        leaves=[tables['trees'][i]['leaves'][j] for i,j in enumerate(row['leaves'])]
        expected=sum(model['trees'][i]['value'][l['node']][0][1]/sum(model['trees'][i]['value'][l['node']][0]) for i,l in enumerate(leaves))/3
        assert row['probability_score']==8*int(expected>.5)
        assert row['majority_score']==8*int(sum(np.argmax(model['trees'][i]['value'][l['node']][0]) for i,l in enumerate(leaves))>=2)
    for enc in tables['encoders']:
        cover=np.zeros(65536,dtype=int)
        for r in enc['rows']:cover[r['low']:r['high']+1]+=1
        assert np.all(cover==1)
    result={'status':'PASS_OFFLINE_EQUIVALENCE','model_sha256':MODEL_SHA,'fitted_sha256':digest(fitted_path),'fitted_origin':'New fit from retained inputs, supplied object; no refit or reconstruction performed','environment':{'Python':platform.python_version(),'sklearn':sklearn.__version__,'numpy':np.__version__,'joblib':joblib.__version__,'scipy':scipy.__version__},'class_order':[0,1],'feature_order':FEATURES,'input_conversion':'uint16: first five retained features plus zero bigram, as supplied training script','exact_arrays':arrays,'checked_inputs':total,'groups':reports,'maximum_probability_difference':maxdiff,'domain_cells':60,'whole_uint16_encoder_domain_coverage':True,'aggregation_combinations':512,'majority_disagreement_cells':disagreements,'metrics':comparison,'labels_note':'Background class 0 is nominally benign; retained labels are not independently verified ground truth. These are retained train/development measurements, not new held-out/full-run outcomes.'}
    with args.out.open('x') as f:json.dump(result,f,indent=2)
    print(json.dumps({'status':result['status'],'checked_inputs':total,'maximum_probability_difference':maxdiff,'metrics':comparison,'majority_disagreement_cells':len(disagreements)}))

if __name__=='__main__':main()
