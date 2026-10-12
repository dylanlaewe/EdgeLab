#!/usr/bin/env python3
import base64,hashlib,tempfile
from pathlib import Path
def reconstruct(graph):
 d=tempfile.TemporaryDirectory();root=Path(d.name)
 blobs={x['id']:x for x in graph['blobs']}
 for a in graph['artifacts']:
  b=blobs[a['blob_id']];data=base64.b64decode(b['bytes_b64']);
  if hashlib.sha256(data).hexdigest()!=b['sha256']:raise ValueError('blob digest')
  p=root/a['path'];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 return d,root
