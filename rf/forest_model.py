import json,hashlib,pathlib,math
FEATURES=['zone_rate_k','distinct_est_k','src_spread_k','client_zone_rate_k','nxd_count_k','bigram_k']
MODEL_SHA256='24027905ccd718b7544cc7e06022aff2bb86aef60129e6f09f36d6274188a745'
def digest(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def load(path=None):
 path=pathlib.Path(path) if path else pathlib.Path(__file__).parent/'model/forest.json'
 if digest(path)!=MODEL_SHA256:raise ValueError('Frozen forest hash changed')
 model=json.loads(path.read_text());p=model['params']
 if model['features']!=FEATURES or len(model['trees'])!=3 or p['n_estimators']!=3 or p['max_depth']!=3 or p['random_state']!=42 or p['max_features'] is not None or not p['bootstrap'] or p['class_weight']!='balanced':raise ValueError('Frozen forest configuration changed')
 if len(model['table_rows'])!=22 or sum(r['score']==8 for r in model['table_rows'])!=8:raise ValueError('Frozen regions changed')
 for tree in model['trees']:
  def depth(n):return 0 if tree['children_left'][n]<0 else 1+max(depth(tree['children_left'][n]),depth(tree['children_right'][n]))
  if depth(0)>3:raise ValueError('Tree depth changed')
 return model
def probabilities(model,features):
 if len(features)!=6 or any(type(int(v)) is not int or not 0<=int(v)<=65535 for v in features):raise ValueError('Six finite-width features required')
 values=[]
 for tree in model['trees']:
  node=0
  while tree['children_left'][node]>=0:
   node=tree['children_left'][node] if features[tree['feature'][node]]<=tree['threshold'][node] else tree['children_right'][node]
  leaf=tree['value'][node][0];values.append(leaf[1]/sum(leaf))
 return values
def predict(model,features):return int(sum(probabilities(model,features))/3>0.5)
def matching_region(model,features):
 rows=[r for r in model['table_rows'] if all(lo<=int(v)<=hi for v,(lo,hi) in zip(features,r['bounds']))]
 if len(rows)!=1:raise ValueError('Missing or ambiguous portable region')
 if int(rows[0]['score']>0)!=predict(model,features):raise ValueError('Region disagrees with probability average')
 return rows[0]
