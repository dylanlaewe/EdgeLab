#!/usr/bin/env python3
"""Reference-only replay for authentic frozen M0.2 captures; never a scheduler."""
from __future__ import annotations
import hashlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def replay(name:str):
 base = ROOT/'tests/fixtures/authentic-stage1-dependency' if name.startswith('dependency:') else ROOT/'tests/fixtures/authentic-stage1'
 fixture=base/(name.split(':',1)[1] if name.startswith('dependency:') else name); manifest=json.loads((fixture/'capture.json').read_text())
 with tempfile.TemporaryDirectory() as td:
  repo=Path(td)/'repository';shutil.copytree(fixture/'repository',repo,ignore=shutil.ignore_patterns('.git','__pycache__'))
  subprocess.run(['git','init','-q',str(repo)],check=True);subprocess.run(['git','-C',str(repo),'config','user.email','replay@example.invalid'],check=True);subprocess.run(['git','-C',str(repo),'config','user.name','replay'],check=True);subprocess.run(['git','-C',str(repo),'add','.'],check=True);subprocess.run(['git','-C',str(repo),'commit','-qm','replay'],check=True);subprocess.run(['git','-C',str(repo),'remote','add','origin','https://github.com/dylanlaewe/EdgeLab.git'],check=True);subprocess.run(['git','-C',str(repo),'update-ref','refs/remotes/origin/main','HEAD'],check=True)
  inventory=hashlib.sha256(b''.join(sorted((str(p.relative_to(repo))+':'+sha(p)).encode() for p in repo.rglob('*') if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts))).hexdigest()
  if 'repository_inventory_sha256' in manifest and inventory != manifest['repository_inventory_sha256']: raise RuntimeError('retained repository bytes changed')
  package_paths=[str(p) for p in (fixture/'packages').iterdir()] if (fixture/'packages').exists() else [str(fixture/p['path']) for p in manifest['packages']]
  code="from pathlib import Path;import json;from edgelab.orchestration import decision;print(json.dumps(decision(Path('repository'),json.loads('''%s''')),sort_keys=True,separators=(',',':')))" % json.dumps(manifest['intent'])
  env={'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','LC_ALL':'C.UTF-8','TZ':'UTC','PYTHONIOENCODING':'utf-8','PATH':os.environ['PATH'],'PYTHONPATH':os.pathsep.join([str(repo/'src'),*package_paths])}
  got=json.loads(subprocess.check_output([sys.executable,'-S','-c',code],cwd=Path(td),env=env,text=True))
  if got != manifest['result']: raise RuntimeError('frozen replay output differs')
  return got
if __name__=='__main__': print(json.dumps(replay(sys.argv[1]),sort_keys=True))
