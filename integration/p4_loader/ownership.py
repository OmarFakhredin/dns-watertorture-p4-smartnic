
                                                                         
import os as _release_os
if _release_os.environ.get('DNS_RESEARCH_ENABLE_SITE_TOOLS') != 'I_HAVE_REVIEWED_SITE_CONFIGURATION':
    raise RuntimeError('Site tools are inactive. See docs/MODEL_BLUEFIELD.md and site.example.json.')
import argparse
import json
import os
import pathlib
import sys
import time

sys.path[:0] = ['/SITE_HOME/open-p4studio/install/lib/python3.8/site-packages/tofino', '/SITE_HOME/open-p4studio/install/lib/python3.8/site-packages']



def owned_namespace(runtime):
    identity = json.loads((runtime / 'model_identity.json').read_text())
    proc = pathlib.Path('/proc') / str(identity['pid'])
    ticks = proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
    if ticks != str(identity['start_ticks']):
        raise RuntimeError('Owned model identity changed')
    current = os.readlink('/proc/self/ns/net')
    if current != os.readlink(str(proc / 'ns/net')) or current == os.readlink('/proc/1/ns/net'):
        raise RuntimeError('Refusing a production or different network namespace')


