from pathlib import Path
import json, subprocess, sys
ROOT=Path(__file__).resolve().parents[1]

def _run(*args):
    cp=subprocess.run([sys.executable,str(ROOT/'run_pde.py'),*map(str,args)],cwd=ROOT,text=True,capture_output=True)
    return cp, json.loads(cp.stdout) if cp.stdout.strip() else None

def test_heat_cli_binding_is_clean():
    cp,obj=_run(ROOT/'examples'/'heat_neumann.model.json','--query',ROOT/'examples'/'heat_mean.query.json')
    assert cp.returncode==0
    assert obj['binding_valid'] is True and obj['normalization_results']==['VALID']
    assert obj['query']['kind']=='LAW' and obj['query']['reader_id']=='one'

def test_interface_cli_binding_is_clean():
    cp,obj=_run(ROOT/'examples'/'two_cell_interface.bundle.json')
    assert cp.returncode==0
    assert obj['binding_valid'] is True and len(obj['models'])==2 and len(obj['couplings'])==1


def test_interface_cli_automatic_composition_is_clean():
    cp,obj=_run(ROOT/'examples'/'two_cell_interface.bundle.json','--query',ROOT/'examples'/'two_cell_global_mean.query.json','--auto-evidence')
    assert cp.returncode==0, cp.stderr
    ae=obj['auto_evidence']
    assert ae['status']=='VALID'
    assert ae['output']['kind']=='EXACT_LAW'
    assert ae['law']['eliminated_couplings']==['flux_glue']
    assert all('flux' not in x['object'] for x in ae['output']['value']['retained_terms'])
