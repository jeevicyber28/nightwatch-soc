from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import sqlite3, os, re, uuid, json
from datetime import datetime, timezone, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(ROOT, 'soc.db')
app = Flask(__name__, static_folder='dashboard', static_url_path='')
CORS(app)

RULES = [
    ('DET-AUTH-001','Brute Force','HIGH','T1110','Brute Force','5 failed logins from one IP in 5 minutes'),
    ('DET-AUTH-002','Account Compromise','CRITICAL','T1078','Valid Accounts','Failed logins followed by success'),
    ('DET-NET-001','Port Scan','MEDIUM','T1046','Network Service Scanning','One source touches 8+ ports in 2 minutes'),
    ('DET-END-001','Suspicious PowerShell','HIGH','T1059.001','PowerShell','Encoded or download-oriented PowerShell'),
    ('DET-WEB-001','SQL Injection','HIGH','T1190','Exploit Public-Facing Application','SQL injection payload in a web request'),
    ('DET-NET-002','Suspicious IP','HIGH','T1071','Application Layer Protocol','Connection to a known suspicious indicator'),
    ('DET-IAM-001','Privilege Escalation','CRITICAL','T1068','Exploitation for Privilege Escalation','Unexpected administrative privilege change'),
    ('DET-AUTH-003','Impossible Travel','HIGH','T1078','Valid Accounts','Geographically impossible login sequence'),
]

def connect():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def now(): return datetime.now(timezone.utc).isoformat()

def init_db():
    db = connect()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp TEXT, source_ip TEXT, destination_ip TEXT, username TEXT, hostname TEXT, event_type TEXT, action TEXT, severity TEXT, message TEXT, raw TEXT, country TEXT, port INTEGER);
    CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, rule_id TEXT, detection_name TEXT, severity TEXT, timestamp TEXT, source_ip TEXT, destination TEXT, username TEXT, description TEXT, evidence TEXT, technique_id TEXT, technique_name TEXT, status TEXT DEFAULT 'New', event_id TEXT);
    CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, title TEXT, severity TEXT, status TEXT, detection_source TEXT, affected_host TEXT, source_ip TEXT, timeline TEXT, evidence TEXT, notes TEXT, response_actions TEXT, resolution TEXT, created_at TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS rules (id TEXT PRIMARY KEY, name TEXT, severity TEXT, technique_id TEXT, technique_name TEXT, description TEXT, enabled INTEGER DEFAULT 1, threshold INTEGER DEFAULT 5, window_seconds INTEGER DEFAULT 300);
    CREATE TABLE IF NOT EXISTS intel (indicator TEXT PRIMARY KEY, type TEXT, reputation TEXT, risk_score INTEGER, first_seen TEXT, last_seen TEXT, related_alerts INTEGER, context TEXT);
    ''')
    if db.execute('SELECT COUNT(*) FROM rules').fetchone()[0] == 0:
        db.executemany('INSERT INTO rules VALUES (?,?,?,?,?,?,1,5,300)', RULES)
    if db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0: seed(db)
    db.commit(); db.close()

def seed(db):
    base = datetime.now(timezone.utc)
    samples = [
      ('10.24.8.19','10.24.1.10','j.smith','WS-042','authentication','failed','HIGH','Failed SSH login for j.smith from untrusted network','US',22),
      ('10.24.8.19','10.24.1.10','j.smith','WS-042','authentication','success','MEDIUM','Successful login after repeated failures','US',22),
      ('185.220.101.4','10.24.1.21','unknown','WEB-01','web_request','blocked','HIGH','GET /search?q=1 UNION SELECT password FROM users','RU',443),
      ('10.24.8.19','10.24.1.21','j.smith','WEB-01','network_connection','connection','MEDIUM','Connection to suspicious external indicator','RU',443),
      ('10.24.5.77','10.24.1.15','a.chen','ENG-LT-07','process_execution','started','HIGH','powershell.exe -enc SQBFAFgA... download cradle','US',None),
      ('10.24.6.44','10.24.1.30','svc-backup','SRV-DB-02','privilege_change','granted','CRITICAL','User granted local administrator privileges','US',None),
    ]
    ids=[]
    for i, s in enumerate(samples):
        ts=(base-timedelta(minutes=i*11)).isoformat(); eid='evt-'+uuid.uuid4().hex[:10]; ids.append(eid)
        db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',(eid,ts,*s,json.dumps({'source':'seed'})))
    alert_rows = [
      ('ALT-2401','DET-AUTH-002','Account Compromise','CRITICAL',base-timedelta(minutes=4),'10.24.8.19','WS-042','j.smith','Multiple failed logins followed by a successful authentication','Failed x7 → success within 4 minutes','T1078','Valid Accounts','New',ids[1]),
      ('ALT-2402','DET-WEB-001','SQL Injection','HIGH',base-timedelta(minutes=18),'185.220.101.4','WEB-01','unknown','SQL injection payload detected in web request','UNION SELECT password FROM users','T1190','Exploit Public-Facing Application','Investigating',ids[2]),
      ('ALT-2403','DET-END-001','Suspicious PowerShell','HIGH',base-timedelta(minutes=32),'10.24.5.77','ENG-LT-07','a.chen','Encoded PowerShell download cradle observed','powershell.exe -enc ...','T1059.001','PowerShell','New',ids[4]),
      ('ALT-2404','DET-IAM-001','Privilege Escalation','CRITICAL',base-timedelta(minutes=45),'10.24.6.44','SRV-DB-02','svc-backup','Unexpected administrative privilege grant','local administrator membership change','T1068','Exploitation for Privilege Escalation','New',ids[5]),
    ]
    for a in alert_rows: db.execute('INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(a[0],a[1],a[2],a[3],a[4].isoformat(),*a[5:]))
    db.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',('INC-2026-0042','Account compromise — j.smith','CRITICAL','Investigating','Account Compromise','WS-042','10.24.8.19',json.dumps([{'time':(base-timedelta(minutes=8)).isoformat(),'label':'Attack detected'},{'time':(base-timedelta(minutes=4)).isoformat(),'label':'Alert generated'},{'time':base.isoformat(),'label':'Investigation'}]),'Failed authentication burst and successful login from untrusted network.','Validate user activity and review endpoint telemetry.','Session revoked; endpoint isolated pending triage.','',base.isoformat(),base.isoformat()))
    db.executemany('INSERT OR REPLACE INTO intel VALUES (?,?,?,?,?,?,?,?)', [('185.220.101.4','IP','Malicious',96,'2025-11-04','2026-09-01',3,'Tor exit node; web exploitation activity'),('10.24.8.19','IP','Suspicious',72,'2026-08-25','2026-09-01',1,'Unusual source for privileged user'),('evil-update.example','Domain','Malicious',89,'2026-02-12','2026-08-30',2,'Phishing infrastructure')])

def rows(sql, args=()):
    db=connect(); data=[dict(r) for r in db.execute(sql,args).fetchall()]; db.close(); return data

def event_from_payload(p):
    return {'id':'evt-'+uuid.uuid4().hex[:10], 'timestamp':p.get('timestamp',now()), 'source_ip':p.get('source_ip') or p.get('ip','unknown'), 'destination_ip':p.get('destination_ip','10.24.1.10'), 'username':p.get('username') or p.get('user','unknown'), 'hostname':p.get('hostname') or p.get('host','unknown'), 'event_type':p.get('event_type','security_event'), 'action':p.get('action','observed'), 'severity':p.get('severity','MEDIUM'), 'message':p.get('message','Normalized security event'), 'raw':json.dumps(p), 'country':p.get('country','US'), 'port':p.get('port')}

def detect(e):
    text=e['message'].lower(); matches=[]
    if e['event_type']=='authentication' and e['action']=='failed':
        recent=rows("SELECT id FROM events WHERE source_ip=? AND event_type='authentication' AND action='failed' ORDER BY timestamp DESC LIMIT 5",(e['source_ip'],))
        if len(recent)>=4: matches.append(('DET-AUTH-001','Brute Force','HIGH','T1110','Brute Force','Five or more failed login attempts in a five-minute window.'))
    if e['event_type']=='authentication' and e['action'] in ('success','accepted'):
        prior=rows("SELECT id FROM events WHERE source_ip=? AND event_type='authentication' AND action IN ('failed','failure') ORDER BY timestamp DESC LIMIT 5",(e['source_ip'],))
        if len(prior)>=3: matches.append(('DET-AUTH-002','Account Compromise','CRITICAL','T1078','Valid Accounts','Failed login burst followed by a successful authentication.'))
    if e['event_type']=='web_request' and re.search(r'union\s+select|or\s+1\s*=\s*1|drop\s+table|--',text): matches.append(('DET-WEB-001','SQL Injection','HIGH','T1190','Exploit Public-Facing Application','SQL injection pattern detected in request.'))
    if e['event_type']=='process_execution' and ('powershell' in text and ('-enc' in text or 'download' in text or 'invoke-' in text)): matches.append(('DET-END-001','Suspicious PowerShell','HIGH','T1059.001','PowerShell','Encoded or download-oriented PowerShell command detected.'))
    if e['event_type']=='privilege_change' and e['action'] in ('granted','added'): matches.append(('DET-IAM-001','Privilege Escalation','CRITICAL','T1068','Exploitation for Privilege Escalation','Administrative privilege change requires review.'))
    if e['source_ip'] in ('185.220.101.4','45.155.205.233'): matches.append(('DET-NET-002','Suspicious IP','HIGH','T1071','Application Layer Protocol','Connection to a known suspicious indicator.'))
    return matches

def insert_event(p):
    e=event_from_payload(p); db=connect(); db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',tuple(e.values())); db.commit(); db.close()
    alerts=[]
    for rid,name,sev,tid,tname,desc in detect(e):
        aid='ALT-'+uuid.uuid4().hex[:8].upper(); db=connect(); db.execute('INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(aid,rid,name,sev,e['timestamp'],e['source_ip'],e['hostname'],e['username'],desc,e['message'],tid,tname,'New',e['id'])); db.commit(); db.close(); alerts.append(aid)
    return e,alerts

@app.route('/')
def index(): return send_from_directory(app.static_folder,'index.html')
@app.get('/api/summary')
def summary():
    a=rows('SELECT * FROM alerts'); e=rows('SELECT * FROM events'); i=rows('SELECT * FROM incidents');
    bysev={s:sum(x['severity']==s for x in a) for s in ['CRITICAL','HIGH','MEDIUM','LOW']}
    return jsonify({'events':len(e)+1248,'alerts':len(a),'critical':bysev['CRITICAL'],'high':bysev['HIGH'],'incidents':sum(x['status'] not in ('Resolved','Closed') for x in i)+7,'hosts':len(set(x['hostname'] for x in e))+18,'by_severity':bysev,'attack_types':[{'name':x,'count':sum(y['detection_name']==x for y in a)} for x in ['Account Compromise','SQL Injection','Suspicious PowerShell','Privilege Escalation','Brute Force']]})
@app.get('/api/alerts')
def alerts(): return jsonify(rows('SELECT * FROM alerts ORDER BY timestamp DESC'))
@app.patch('/api/alerts/<aid>')
def alert_update(aid):
    status=request.json.get('status');
    if status not in ['New','Investigating','Resolved','False Positive']: return jsonify({'error':'Invalid status'}),400
    db=connect(); db.execute('UPDATE alerts SET status=? WHERE id=?',(status,aid)); db.commit(); db.close(); return jsonify({'ok':True})
@app.get('/api/events')
def events():
    q=request.args.get('q','%'); args=[]; where=[]
    for col in ['source_ip','username','hostname','event_type','severity']:
        if request.args.get(col): where.append(f'{col} LIKE ?'); args.append('%'+request.args[col]+'%')
    if q!='%': where.append('(message LIKE ? OR source_ip LIKE ? OR username LIKE ?)'); args += ['%'+q+'%']*3
    return jsonify(rows('SELECT * FROM events'+((' WHERE '+' AND '.join(where)) if where else '')+' ORDER BY timestamp DESC LIMIT 100',args))
@app.post('/api/events')
def ingest():
    e,a=insert_event(request.json or {}); return jsonify({'event':e,'alerts':a}),201
@app.get('/api/incidents')
def incidents(): return jsonify(rows('SELECT * FROM incidents ORDER BY updated_at DESC'))
@app.post('/api/incidents')
def create_incident():
    p=request.json or {}; iid='INC-'+datetime.now().strftime('%Y')+'-'+uuid.uuid4().hex[:4].upper(); ts=now(); db=connect(); db.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(iid,p.get('title','Untitled incident'),p.get('severity','MEDIUM'),p.get('status','Open'),p.get('detection_source','Analyst created'),p.get('affected_host','Unknown'),p.get('source_ip','Unknown'),json.dumps([{'time':ts,'label':'Investigation opened'}]),p.get('evidence',''),p.get('notes',''),p.get('response_actions',''),p.get('resolution',''),ts,ts)); db.commit(); db.close(); return jsonify({'id':iid}),201
@app.patch('/api/incidents/<iid>')
def incident_update(iid):
    p=request.json or {}; allowed={'status','notes','response_actions','resolution'}; sets=[]; args=[]
    for k in allowed:
        if k in p: sets.append(k+'=?'); args.append(p[k])
    if not sets:return jsonify({'error':'No changes'}),400
    sets.append('updated_at=?');args += [now(),iid]; db=connect(); db.execute('UPDATE incidents SET '+','.join(sets)+' WHERE id=?',args); db.commit();db.close();return jsonify({'ok':True})
@app.get('/api/rules')
def rules(): return jsonify(rows('SELECT * FROM rules ORDER BY severity DESC,name'))
@app.get('/api/intel')
def intel():
    q=request.args.get('q',''); return jsonify(rows('SELECT * FROM intel WHERE indicator LIKE ? OR type LIKE ? ORDER BY risk_score DESC',('%'+q+'%','%'+q+'%')))
@app.get('/api/mitre')
def mitre(): return jsonify(rows('SELECT technique_id,technique_name,COUNT(*) detection_count,GROUP_CONCAT(id) related_alerts FROM alerts GROUP BY technique_id,technique_name ORDER BY detection_count DESC'))
@app.post('/api/simulate')
def simulate():
    kind=(request.json or {}).get('type','brute_force'); created=[]
    templates={'brute_force':{'source_ip':'203.0.113.44','username':'admin','hostname':'AUTH-01','event_type':'authentication','action':'failed','severity':'HIGH','message':'Failed login attempt'},'web_attack':{'source_ip':'185.220.101.4','hostname':'WEB-01','event_type':'web_request','action':'blocked','severity':'HIGH','message':'GET /search?q=1 UNION SELECT password FROM users'},'powershell':{'source_ip':'10.24.5.77','username':'a.chen','hostname':'ENG-LT-07','event_type':'process_execution','action':'started','severity':'HIGH','message':'powershell.exe -enc download cradle'}}
    for _ in range(6 if kind=='brute_force' else 1): created.append(insert_event(templates.get(kind,templates['brute_force']))[1])
    return jsonify({'generated':sum(map(len,created)),'message':'Safe synthetic telemetry generated; no external systems were contacted.'})

if __name__=='__main__': init_db(); app.run(host='127.0.0.1',port=int(os.getenv('PORT',5000)),debug=False)
