import hashlib, os, uuid
from pathlib import Path
from urllib.parse import quote
import requests

class LocalStorageProvider:
    def __init__(self, root): self.root=Path(root).resolve(); self.root.mkdir(parents=True,exist_ok=True)
    def put(self, stream):
        key=uuid.uuid4().hex; path=self.root/key; h=hashlib.sha256(); size=0
        with path.open('wb') as out:
            while True:
                chunk=stream.read(1024*1024)
                if not chunk: break
                out.write(chunk); h.update(chunk); size+=len(chunk)
        return key,size,h.hexdigest()
    def path(self,key):
        if not key or Path(key).name != key: raise ValueError('Invalid storage key')
        path=(self.root/key).resolve()
        if path.parent != self.root: raise ValueError('Invalid storage key')
        return path
    def read(self,key): return self.path(key).read_bytes()
    def delete(self,key): self.path(key).unlink(missing_ok=True)

class SupabaseStorageProvider:
    """Private bucket adapter using authenticated server-side Storage REST calls."""
    _private_buckets=set()
    def __init__(self,url,key,bucket):
        self.url=url.rstrip('/'); self.bucket=bucket; self.base=self.url+'/storage/v1/object/'+quote(bucket,safe=''); self.bucket_url=self.url+'/storage/v1/bucket/'+quote(bucket,safe=''); self.key=key
    @property
    def headers(self): return {'Authorization':'Bearer '+self.key,'apikey':self.key}
    def validate_private_bucket(self):
        cache_key=(self.url,self.bucket)
        if cache_key in self._private_buckets: return
        response=requests.get(self.bucket_url,headers=self.headers,timeout=20); response.raise_for_status()
        bucket=response.json()
        if bucket.get('public') is not False: raise ValueError('Configured Supabase bucket must exist and be private.')
        self._private_buckets.add(cache_key)
    def put(self,stream):
        self.validate_private_bucket()
        data=stream.read(); key=uuid.uuid4().hex
        response=requests.post(self.base+'/'+quote(key,safe=''),headers={**self.headers,'x-upsert':'false','Content-Type':'application/octet-stream'},data=data,timeout=60); response.raise_for_status()
        return key,len(data),hashlib.sha256(data).hexdigest()
    def read(self,key):
        self.validate_private_bucket()
        response=requests.get(self.base+'/'+quote(key,safe=''),headers=self.headers,timeout=60)
        if response.status_code==404: raise FileNotFoundError(key)
        response.raise_for_status()
        return response.content
    def delete(self,key):
        self.validate_private_bucket()
        response=requests.delete(self.base+'/'+quote(key,safe=''),headers=self.headers,timeout=30)
        if response.status_code==404: return
        response.raise_for_status()

def provider(config):
    if config['STORAGE_BACKEND']=='supabase': return SupabaseStorageProvider(config['SUPABASE_URL'],config['SUPABASE_KEY'],config['SUPABASE_BUCKET'])
    return LocalStorageProvider(config['LOCAL_STORAGE_PATH'])
