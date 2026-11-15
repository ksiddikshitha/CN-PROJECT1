import io, os, tempfile, hashlib
import pytest
from app import create_app, db
from app.models import User, File, Folder

@pytest.fixture()
def client(tmp_path):
    app=create_app({'TESTING':True,'SECRET_KEY':'test-secret-key','WTF_CSRF_ENABLED':False,'PASSWORD_RESET_LOG_LINKS':True,'SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(tmp_path/'test.db'),'LOCAL_STORAGE_PATH':str(tmp_path/'files'),'USER_QUOTA_BYTES':1024*1024,'MAX_CONTENT_LENGTH':2*1024*1024,'RATELIMIT_ENABLED':False})
    with app.test_client() as client:
        with app.app_context(): db.drop_all(); db.create_all()
        yield client
        with app.app_context(): db.session.remove(); db.drop_all()

def register(client,email='a@example.com',password='CorrectHorse123!'):
    return client.post('/register',data={'name':'Test User','email':email,'password':password,'confirm':password},follow_redirects=True)

def test_register_login_logout(client):
    response=register(client)
    assert response.status_code==200 and b'Good to see you' in response.data
    with client.application.app_context():
        user=User.query.filter_by(email='a@example.com').one()
        assert user.password_hash!='CorrectHorse123!' and user.check_password('CorrectHorse123!')
    client.post('/logout')
    assert client.get('/dashboard').status_code==302
    assert client.post('/login',data={'email':'a@example.com','password':'CorrectHorse123!'}).status_code==302

def test_upload_download_integrity_and_owner_isolation(client):
    register(client)
    data=b'CloudLock integrity test'
    response=client.post('/upload',data={'files':(io.BytesIO(data),'notes.txt')},content_type='multipart/form-data',follow_redirects=True)
    assert response.status_code==200 and b'notes.txt' in response.data
    with client.application.app_context():
        f=File.query.one(); fid=f.id; assert f.sha256==hashlib.sha256(data).hexdigest()
    assert client.get(f'/file/{fid}/download').data==data
    with client.application.app_context():
        from app.storage import provider
        stored=provider(client.application.config).path(db.session.get(File,fid).storage_key)
        stored.write_bytes(b'tampered content')
    assert client.get(f'/file/{fid}/download').status_code==500
    client.post('/logout'); register(client,'b@example.com')
    assert client.get(f'/file/{fid}/download').status_code==404

def test_share_password_download_and_revoke(client):
    register(client)
    client.post('/upload',data={'files':(io.BytesIO(b'shared text'),'share.txt')},content_type='multipart/form-data')
    with client.application.app_context(): fid=File.query.one().id
    client.post(f'/share/{fid}',data={'password':'linksecret','download':'on','limit':'1'})
    with client.session_transaction() as session:
        message=session['_flashes'][-1][1]
    token=message.rsplit('/s/',1)[1]
    assert client.get('/s/'+token).status_code==200
    assert b'password protected' in client.get('/s/'+token).data
    assert b'Incorrect password' in client.post('/s/'+token,data={'password':'wrong'}).data
    assert client.post('/s/'+token,data={'password':'linksecret'}).status_code==200
    assert client.get('/s/'+token+'?download=1').data==b'shared text'
    assert client.get('/s/'+token).status_code==404
    client.post('/share/revoke/1')
    assert client.get('/s/'+token).status_code==404
    client.post('/logout'); register(client,'b@example.com')
    assert client.post('/share/revoke/1').status_code==404

def test_expired_share_and_duplicate_detection(client):
    register(client)
    data=b'duplicate contents'
    client.post('/upload',data={'files':(io.BytesIO(data),'first.txt')},content_type='multipart/form-data')
    response=client.post('/upload',data={'files':(io.BytesIO(data),'second.txt')},content_type='multipart/form-data',follow_redirects=True)
    assert b'identical content exists' in response.data
    with client.application.app_context(): fid=File.query.one().id
    client.post(f'/share/{fid}',data={'download':'on'})
    with client.session_transaction() as session: token=session['_flashes'][-1][1].rsplit('/s/',1)[1]
    from datetime import datetime, timedelta, timezone
    from app.models import ShareLink
    with client.application.app_context():
        link=ShareLink.query.one(); link.expires_at=datetime.now(timezone.utc)-timedelta(days=1); db.session.commit()
    assert client.get('/s/'+token).status_code==404

def test_search_favorite_trash_restore(client):
    register(client)
    client.post('/upload',data={'files':(io.BytesIO(b'alpha'),'alpha.txt')},content_type='multipart/form-data')
    with client.application.app_context(): fid=File.query.one().id
    assert b'alpha.txt' in client.get('/files?q=alpha').data
    client.post(f'/file/{fid}/favorite')
    assert b'alpha.txt' in client.get('/favorites').data
    client.post(f'/file/{fid}/delete')
    assert b'alpha.txt' in client.get('/trash').data
    client.post(f'/file/{fid}/restore')
    assert b'alpha.txt' in client.get('/files').data

def test_folder_creation_and_unauthenticated_pages(client):
    assert client.get('/dashboard').status_code==302
    assert client.get('/').status_code==200
    register(client)
    response=client.post('/folders',data={'name':'Coursework'},follow_redirects=True)
    assert response.status_code==200 and b'Coursework' in response.data
    for path in ['/analytics','/activity','/settings','/shared','/network']:
        assert client.get(path).status_code==200

def test_file_rename_move_and_nested_folder_management(client):
    register(client)
    client.post('/folders',data={'name':'Coursework'})
    with client.application.app_context(): root=Folder.query.filter_by(name='Coursework').one().id
    client.post('/folders',data={'name':'Networks','parent_id':str(root)})
    client.post('/folders',data={'name':'Archive'})
    with client.application.app_context(): child=Folder.query.filter_by(name='Networks').one().id; archive=Folder.query.filter_by(name='Archive').one().id
    assert b'Networks' in client.get(f'/folders/{root}').data
    assert client.post(f'/folder/{child}/rename',data={'name':'CN Lab'}).status_code==302
    assert b'CN Lab' in client.get(f'/folders/{root}').data
    client.post('/upload',data={'files':(io.BytesIO(b'rename me'),'original.txt')},content_type='multipart/form-data')
    with client.application.app_context(): fid=File.query.one().id
    assert client.post(f'/file/{fid}/rename',data={'name':'renamed.txt'}).status_code==302
    assert client.post(f'/file/{fid}/move',data={'folder_id':str(child)}).status_code==302
    assert b'renamed.txt' in client.get(f'/folders/{child}').data
    # Moving a parent into a descendant is rejected to prevent cycles.
    assert client.post(f'/folder/{root}/move',data={'parent_id':str(child)}).status_code==400
    assert client.post(f'/folder/{child}/move',data={'parent_id':str(archive)}).status_code==302
    assert b'CN Lab' in client.get(f'/folders/{archive}').data
    client.post('/folders',data={'name':'Empty'})
    with client.application.app_context(): empty=Folder.query.filter_by(name='Empty').one().id
    client.post(f'/folder/{empty}/delete')
    assert b'Empty' in client.get('/trash').data
    client.post(f'/folder/{empty}/restore')
    client.post(f'/folder/{empty}/delete')
    client.post(f'/folder/{empty}/purge')
    with client.application.app_context(): assert db.session.get(Folder,empty) is None

def test_recycle_bin_permanent_delete_and_empty(client):
    register(client)
    client.post('/upload',data={'files':(io.BytesIO(b'delete me'),'delete.txt')},content_type='multipart/form-data')
    with client.application.app_context():
        f=File.query.one(); fid=f.id; key=f.storage_key; storage=__import__('app.storage',fromlist=['provider']).provider(client.application.config)
    client.post(f'/file/{fid}/delete')
    assert client.post(f'/file/{fid}/purge').status_code==302
    with client.application.app_context():
        assert db.session.get(File,fid) is None
        assert not storage.path(key).exists()
    client.post('/upload',data={'files':(io.BytesIO(b'clear me'),'clear.txt')},content_type='multipart/form-data')
    with client.application.app_context(): fid=File.query.one().id
    client.post(f'/file/{fid}/delete')
    assert client.post('/trash/empty').status_code==302
    with client.application.app_context(): assert File.query.count()==0

def test_shared_with_me_grant_password_and_permissions(client):
    register(client)
    client.post('/upload',data={'files':(io.BytesIO(b'recipient data'),'recipient.txt')},content_type='multipart/form-data')
    with client.application.app_context(): fid=File.query.one().id
    client.post('/logout'); register(client,'b@example.com'); client.post('/logout')
    client.post('/login',data={'email':'a@example.com','password':'CorrectHorse123!'})
    client.post(f'/share/{fid}',data={'recipient_email':'b@example.com','password':'share-pass','download':'on'})
    client.post('/logout'); client.post('/login',data={'email':'b@example.com','password':'CorrectHorse123!'})
    inbox=client.get('/shared-with-me')
    assert inbox.status_code==200 and b'recipient.txt' in inbox.data
    with client.application.app_context(): from app.models import ShareLink; sid=ShareLink.query.one().id
    assert b'password' in client.get(f'/shared-with-me/{sid}').data.lower()
    assert client.get(f'/shared-with-me/{sid}/download').status_code==302
    assert client.post(f'/shared-with-me/{sid}',data={'password':'share-pass'}).status_code==200
    assert client.get(f'/shared-with-me/{sid}/download').data==b'recipient data'
    client.post('/logout'); client.post('/login',data={'email':'a@example.com','password':'CorrectHorse123!'})
    client.post(f'/share/revoke/{sid}')
    client.post('/logout'); client.post('/login',data={'email':'b@example.com','password':'CorrectHorse123!'})
    assert client.get(f'/shared-with-me/{sid}/download').status_code==404
    client.post('/logout'); client.post('/login',data={'email':'a@example.com','password':'CorrectHorse123!'})
    client.post('/upload',data={'files':(io.BytesIO(b'preview only'),'view.txt')},content_type='multipart/form-data')
    with client.application.app_context(): view_id=File.query.filter_by(name='view.txt').one().id
    client.post(f'/share/{view_id}',data={'recipient_email':'b@example.com'})
    client.post('/logout'); client.post('/login',data={'email':'b@example.com','password':'CorrectHorse123!'})
    with client.application.app_context(): view_share=ShareLink.query.filter_by(file_id=view_id).one().id
    assert client.get(f'/shared-with-me/{view_share}/preview').data==b'preview only'
    assert client.get(f'/shared-with-me/{view_share}/download').status_code==403

def test_password_reset_is_hashed_expiring_and_single_use(client,caplog):
    import re, logging
    register(client)
    with caplog.at_level(logging.INFO):
        response=client.post('/forgot-password',data={'email':'a@example.com'},follow_redirects=True)
    assert response.status_code==200 and b'If that account exists' in response.data
    token=re.search(r'/reset/([A-Za-z0-9_-]+)',caplog.text).group(1)
    with client.application.app_context():
        from app.models import PasswordResetToken
        reset=PasswordResetToken.query.one(); assert reset.token_hash!=token and len(reset.token_hash)==64
        from datetime import datetime, timedelta, timezone
        reset.expires_at=datetime.now(timezone.utc)-timedelta(seconds=1); db.session.commit()
    assert client.get('/reset/'+token).status_code==404
    with caplog.at_level(logging.INFO): client.post('/forgot-password',data={'email':'a@example.com'})
    token=re.findall(r'/reset/([A-Za-z0-9_-]+)',caplog.text)[-1]
    assert client.post('/reset/'+token,data={'password':'NewSecurePassword123','confirm':'NewSecurePassword123'}).status_code==302
    client.post('/logout')
    assert client.post('/login',data={'email':'a@example.com','password':'NewSecurePassword123'}).status_code==302
    assert client.get('/reset/'+token).status_code==404

def test_dashboard_category_chart_and_upload_content_validation(client):
    register(client)
    client.post('/upload',data={'files':(io.BytesIO(b'plain text'),'notes.txt')},content_type='multipart/form-data')
    response=client.post('/upload',data={'files':(io.BytesIO(b'plain text'),'bad.pdf')},content_type='multipart/form-data',follow_redirects=True)
    assert b'does not match its extension' in response.data
    dashboard=client.get('/dashboard')
    assert b'File type distribution' in dashboard.data and b'Documents' in dashboard.data
    assert b'100.0%</strong>' in dashboard.data
    assert client.get('/analytics').status_code==200

def test_supabase_storage_rest_adapter_headers_and_operations(monkeypatch):
    from types import SimpleNamespace
    from app.storage import SupabaseStorageProvider
    calls=[]
    def response(payload=b'cloud bytes',status=200):
        return SimpleNamespace(status_code=status,content=payload,json=lambda:{'public':False},raise_for_status=lambda: (_ for _ in ()).throw(Exception('http error')) if status>=400 else None)
    monkeypatch.setattr('app.storage.requests.post',lambda url,**kw:(calls.append(('POST',url,kw)) or response()))
    monkeypatch.setattr('app.storage.requests.get',lambda url,**kw:(calls.append(('GET',url,kw)) or response()))
    monkeypatch.setattr('app.storage.requests.delete',lambda url,**kw:(calls.append(('DELETE',url,kw)) or response()))
    store=SupabaseStorageProvider('https://example.supabase.co','server-secret','private bucket')
    key,size,digest=store.put(io.BytesIO(b'cloud bytes'))
    assert size==11 and len(digest)==64 and calls[1][1].startswith('https://example.supabase.co/storage/v1/object/private%20bucket/')
    assert calls[1][2]['headers']['Authorization']=='Bearer server-secret'
    assert store.read(key)==b'cloud bytes'
    store.delete(key)
    assert [call[0] for call in calls]==['GET','POST','GET','DELETE']

def test_supabase_rejects_public_bucket(monkeypatch):
    from types import SimpleNamespace
    from app.storage import SupabaseStorageProvider
    monkeypatch.setattr('app.storage.requests.get',lambda *a,**kw:SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'public':True}))
    store=SupabaseStorageProvider('https://another.supabase.co','server-secret','public-bucket')
    with pytest.raises(ValueError,match='must exist and be private'):
        store.validate_private_bucket()

def test_missing_supabase_credentials_fall_back_to_local(tmp_path):
    app=create_app({'TESTING':True,'SECRET_KEY':'fallback-test','SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(tmp_path/'fallback.db'),'LOCAL_STORAGE_PATH':str(tmp_path/'fallback-files'),'STORAGE_BACKEND':'supabase','SUPABASE_URL':'','SUPABASE_KEY':'','RATELIMIT_ENABLED':False})
    assert app.config['STORAGE_BACKEND']=='local'

def test_csrf_protects_state_changes(tmp_path):
    app=create_app({'TESTING':True,'SECRET_KEY':'csrf-test','WTF_CSRF_ENABLED':True,'SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(tmp_path/'csrf.db'),'LOCAL_STORAGE_PATH':str(tmp_path/'csrf-files'),'RATELIMIT_ENABLED':False})
    with app.test_client() as client:
        assert client.post('/register',data={'name':'x','email':'x@example.com','password':'CorrectHorse123!','confirm':'CorrectHorse123!'}).status_code==400


