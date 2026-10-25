import base64,csv,io,json,socket,threading,unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from analyzer import analyze,to_csv,csv_safe,LogInputError
from server import Handler

ROOT=Path(__file__).resolve().parent.parent

def fixture(name):return (ROOT/'examples'/name).read_bytes()
def make_rows(rows):
    out=io.StringIO(newline='');w=csv.writer(out);w.writerow(['timestamp','event','username','source_ip','host','service'])
    for row in rows:
        base={'timestamp':'2026-10-25T10:00:00Z','event':'failure','username':'alice','source_ip':'192.0.2.10','host':'lab','service':'ssh'};base.update(row)
        w.writerow([base[k] for k in ('timestamp','event','username','source_ip','host','service')])
    return out.getvalue().encode()
def sequence(n=5,spacing=30,**kwargs):
    start=datetime(2026,10,25,10,tzinfo=timezone.utc)
    return [dict(timestamp=(start+timedelta(seconds=i*spacing)).isoformat(),**kwargs) for i in range(n)]
def rules(report):return report['rule_counts']

class ParsingTests(unittest.TestCase):
    def test_normal_fixture(self):
        r=analyze(fixture('normal.log'));self.assertEqual(r['summary']['parsed_events'],4);self.assertEqual(r['summary']['alerts'],0)
    def test_suspicious_fixture_all_rules(self):
        r=analyze(fixture('suspicious.log'));self.assertEqual(r['summary']['parsed_events'],14);self.assertEqual(r['summary']['failures'],13)
        self.assertEqual(r['summary']['alerts'],5);self.assertEqual(rules(r),{'SLA-001':2,'SLA-002':1,'SLA-003':1,'SLA-004':1})
    def test_normalized_windows_csv(self):
        r=analyze(fixture('normalized.csv'));self.assertEqual(r['format'],'csv');self.assertEqual(r['summary']['successes'],1);self.assertEqual(r['summary']['alerts'],2)
    def test_partial_counts_and_no_raw_messages(self):
        r=analyze(fixture('partial.log'));self.assertEqual(r['parse_status'],'partial')
        self.assertEqual(r['summary']['ignored_records'],2);self.assertEqual(r['summary']['invalid_records'],1);self.assertEqual(r['summary']['parsed_events'],1)
        self.assertNotIn('NOT_AN_IP',json.dumps(r))
    def test_unsupported_input_not_clean(self):
        r=analyze(b'unsupported message\n');self.assertEqual(r['parse_status'],'no_supported_events');self.assertEqual(r['summary']['ignored_records'],1)
    def test_invalid_user_auxiliary_not_double_counted(self):
        data=b'Oct 25 10:00:00 lab sshd[1]: Invalid user bob from 192.0.2.1 port 20\nOct 25 10:00:01 lab sshd[1]: Failed password for invalid user bob from 192.0.2.1 port 20 ssh2\n'
        r=analyze(data);self.assertEqual(r['summary']['parsed_events'],1);self.assertEqual(r['summary']['ignored_records'],1);self.assertTrue(r['events_preview'][0]['invalid_user'])
    def test_syslog_assumptions_explicit(self):
        r=analyze(b'Oct 25 10:00:00 lab sshd[1]: Accepted publickey for bob from 192.0.2.1 port 20 ssh2\n',year=2025,offset='+05:00')
        self.assertEqual(r['events_preview'][0]['timestamp_utc'],'2025-10-25T05:00:00+00:00');self.assertEqual(r['summary']['year_assumed_records'],1);self.assertEqual(r['summary']['offset_assumed_records'],1)
    def test_explicit_offset_takes_precedence(self):
        r=analyze(make_rows([{'timestamp':'2026-10-25T10:00:00+02:00'}]),offset='+05:00')
        self.assertEqual(r['events_preview'][0]['timestamp_utc'],'2026-10-25T08:00:00+00:00');self.assertEqual(r['summary']['offset_assumed_records'],0)
    def test_naive_csv_timestamp(self):
        r=analyze(make_rows([{'timestamp':'2026-10-25 10:00:00'}]),offset='-04:00')
        self.assertEqual(r['events_preview'][0]['timestamp_utc'],'2026-10-25T14:00:00+00:00')
    def test_bad_timestamp_is_record_diagnostic(self):
        r=analyze(make_rows([{'timestamp':'2026-02-30T10:00:00Z'}]));self.assertEqual(r['summary']['invalid_records'],1)
    def test_duplicate_records_reported_not_silently_removed(self):
        r=analyze(make_rows([{}]*5));self.assertEqual(r['summary']['identical_normalized_records'],4);self.assertEqual(r['summary']['parsed_events'],5);self.assertIn('SLA-001',rules(r))
    def test_csv_required_host_and_unique_headers(self):
        for data in (b'timestamp,event,username,source_ip\n',b'timestamp,event,username,source_ip,host,host\n'):
            with self.assertRaises(LogInputError):analyze(data,mode='csv')
    def test_csv_leading_blank_line_and_line_reference(self):
        r=analyze(b'\n'+make_rows([{}]));self.assertEqual(r['events_preview'][0]['source_line'],3)
    def test_utf8_bom_and_empty_binary_limits(self):
        self.assertEqual(analyze(b'\xef\xbb\xbf'+fixture('normal.log'))['summary']['parsed_events'],4)
        for data in (b'',b'\xff\xfe',b'a\x00b',b'x'*(5*1024*1024+1)):
            with self.assertRaises(LogInputError):analyze(data)
    def test_invalid_settings(self):
        for kwargs in ({'year':True},{'year':1500},{'offset':'+15:00'},{'offset':'+14:30'},{'offset':'UTC'},{'failure_threshold':1},{'failure_minutes':0},{'mode':[]}):
            with self.assertRaises(LogInputError):analyze(fixture('normal.log'),**kwargs)
    def test_ipv6_and_sshd_session_variant(self):
        r=analyze(b'2026-10-25T10:00:00Z lab sshd-session[2]: Failed keyboard-interactive/pam for alice from 2001:db8::1 port 50 ssh2\n')
        self.assertEqual(r['events_preview'][0]['source_ip'],'2001:db8::1');self.assertEqual(r['summary']['parsed_events'],1)
    def test_raw_trailing_secret_not_exported(self):
        r=analyze(b'2026-10-25T10:00:00Z lab sshd[1]: Failed password for bob from 192.0.2.1 port 50 ssh2 secret=PRIVATE_TOKEN\n')
        self.assertNotIn('PRIVATE_TOKEN',json.dumps(r));self.assertNotIn('PRIVATE_TOKEN',to_csv(r))

class RuleTests(unittest.TestCase):
    def test_failure_threshold_boundary(self):
        self.assertNotIn('SLA-001',rules(analyze(make_rows(sequence(4)))))
        self.assertIn('SLA-001',rules(analyze(make_rows(sequence(5)))))
    def test_window_inclusive_and_outside(self):
        self.assertIn('SLA-001',rules(analyze(make_rows(sequence(5,75)))))
        self.assertNotIn('SLA-001',rules(analyze(make_rows(sequence(5,76)))))
    def test_no_combining_hosts_or_services(self):
        rows=sequence(6)
        for i,r in enumerate(rows):r['host']='a' if i<3 else 'b'
        self.assertNotIn('SLA-001',rules(analyze(make_rows(rows))))
        for i,r in enumerate(rows):r['host']='a';r['service']='one' if i<3 else 'two'
        self.assertNotIn('SLA-001',rules(analyze(make_rows(rows))))
    def test_distinct_users_not_total_failures(self):
        self.assertNotIn('SLA-002',rules(analyze(make_rows(sequence(6)))))
        rows=sequence(5)
        for i,r in enumerate(rows):r['username']='user'+str(i)
        self.assertIn('SLA-002',rules(analyze(make_rows(rows))))
    def test_distinct_source_rule(self):
        rows=sequence(3)
        for i,r in enumerate(rows):r['source_ip']='192.0.2.'+str(i+1)
        self.assertIn('SLA-003',rules(analyze(make_rows(rows))))
        rows[2]['username']='bob'
        self.assertNotIn('SLA-003',rules(analyze(make_rows(rows))))
    def test_success_after_failures_strict_order(self):
        rows=sequence(3);rows.append({'timestamp':'2026-10-25T10:02:00Z','event':'success'})
        self.assertIn('SLA-004',rules(analyze(make_rows(rows))))
        self.assertIn('SLA-004',rules(analyze(make_rows(list(reversed(rows))))))
    def test_same_timestamp_not_proven_after(self):
        rows=[{}]*3+[{'event':'success'}]
        self.assertNotIn('SLA-004',rules(analyze(make_rows(rows))))
    def test_success_other_key_not_correlated(self):
        rows=sequence(5)+[{'timestamp':'2026-10-25T10:03:00Z','event':'success','host':'different'}]
        self.assertNotIn('SLA-004',rules(analyze(make_rows(rows))))
    def test_success_outside_window_not_correlated(self):
        rows=sequence(3)+[{'timestamp':'2026-10-25T10:30:00Z','event':'success'}]
        self.assertNotIn('SLA-004',rules(analyze(make_rows(rows))))
    def test_successes_do_not_count_as_failures(self):
        self.assertEqual(analyze(make_rows(sequence(10,event='success')))['summary']['alerts'],0)
    def test_one_strongest_window_per_group(self):
        rows=sequence(10)
        self.assertEqual(rules(analyze(make_rows(rows))).get('SLA-001'),1)
    def test_source_lines_match_record_evidence(self):
        r=analyze(make_rows(sequence(5)))
        alert=next(a for a in r['alerts'] if a['rule']=='SLA-001')
        self.assertEqual(alert['evidence']['source_lines'],[2,3,4,5,6])
    def test_no_network(self):
        with patch('socket.socket',side_effect=AssertionError('network')),patch('socket.getaddrinfo',side_effect=AssertionError('DNS')):
            self.assertEqual(analyze(fixture('suspicious.log'))['summary']['alerts'],5)
    def test_csv_formula_guard_and_valid_output(self):
        for value in ('=1+1','+x','-x','@SUM(1)',' \t=1'):
            self.assertTrue(csv_safe(value).startswith("'"))
        report=analyze(fixture('suspicious.log'));rows=list(csv.reader(io.StringIO(to_csv(report))))
        self.assertEqual(len(rows),6);self.assertTrue(all(len(r)==len(rows[0]) for r in rows))

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.url=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def post(self,headers=None,payload=None):
        if payload is None:payload={'data':base64.b64encode(fixture('suspicious.log')).decode(),'filename':'suspicious.log'}
        return urlopen(Request(self.url+'/analyze',data=json.dumps(payload).encode(),headers=headers or {'Content-Type':'application/json','X-Log-Analyzer':'local'}))
    def test_local_upload_end_to_end(self):
        with self.post() as r:d=json.load(r)
        self.assertEqual(d['report']['summary']['alerts'],5);self.assertIn('SLA-001',d['csv'])
    def test_cross_origin_and_missing_header(self):
        for headers in ({'X-Log-Analyzer':'local','Origin':'https://other.test'},{'Content-Type':'application/json'}):
            with self.assertRaises(HTTPError) as e:self.post(headers)
            self.assertEqual(e.exception.code,403)
    def test_bad_base64_rejected(self):
        with self.assertRaises(HTTPError) as e:self.post(payload={'data':'%%%','filename':'x.log'})
        self.assertEqual(e.exception.code,400)
    def test_samples_and_static_allowlist(self):
        with urlopen(self.url+'/sample/normal') as r:self.assertEqual(json.load(r)['filename'],'normal.log')
        with urlopen(self.url) as r:self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy'])
        with self.assertRaises(HTTPError) as e:urlopen(self.url+'/analyzer.py')
        self.assertEqual(e.exception.code,404)

if __name__=='__main__':unittest.main()
