"""Offline authentication-log parsing and explainable time-window rules."""
import argparse,csv,hashlib,io,ipaddress,itertools,json,re,unicodedata,uuid
from collections import Counter,defaultdict,deque
from datetime import datetime,timedelta,timezone
from pathlib import Path

VERSION='0.1.0'
MAX_BYTES=5*1024*1024
MAX_RECORDS=20000
MONTHS={m:i+1 for i,m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())}
PREFIX=re.compile(r'^(?P<ts>\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+sshd(?:-session)?(?:\[\d+\])?:\s+(?P<msg>.*)$')
AUTH=re.compile(r'^(?P<outcome>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+(?P<invalid>invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+\b')
LIMITATIONS=[
 'Alerts are authentication patterns requiring investigation, not proof of an attack or account compromise. User mistakes, shared gateways, automation and log duplication can produce similar patterns.',
 'Only supported OpenSSH Failed/Accepted records or the documented normalized CSV schema are analyzed. Native Windows EVTX/XML, arbitrary vendor logs, raw Windows Event Viewer CSV and application-specific formats are not parsed.',
 'Each rule returns the strongest qualifying window per grouping key in this file, not every episode. Windows include both endpoints; success-after-failures requires failures at strictly earlier timestamps.',
 'Records are sorted by parsed UTC time. Yearless/naive timestamps use your explicit year/fixed UTC offset settings. DST, clock skew, year rollover and missing log segments are not inferred.',
 'Records are not automatically deduplicated. Repeated normalized records are counted and reported; rotation/forwarding duplicates can inflate alerts. A log record is not necessarily a unique connection or human attempt.',
 'A source IP is a logged identifier, not verified attacker identity or location. No DNS, geolocation, reputation lookup, host access or blocking action is performed.',
 'Raw log messages are not exported. Normalized records, usernames, hostnames, service names and IPs remain sensitive; review reports before sharing.',
 'The event preview contains at most 200 chronological records. At most 200 alert details are returned; omitted-alert counts are explicit. Grouped counts may describe overlapping records across rules.',
]

class LogInputError(ValueError):pass


def identifier(value,name,maxlen=255):
    if not isinstance(value,str) or not value.strip() or len(value)>maxlen or any(unicodedata.category(c) in {'Cc','Cf','Cs'} for c in value):
        raise LogInputError(f'Missing, oversized, or non-printable {name}.')
    return value.strip()


def config(year=2026,offset='+00:00',failure_threshold=5,failure_minutes=5):
    if type(year) is not int or not 1970<=year<=2100:raise LogInputError('Log year must be 1970–2100.')
    if not isinstance(offset,str) or not re.fullmatch(r'[+-]\d{2}:\d{2}',offset):raise LogInputError('Timezone must be a fixed offset such as +00:00 or +05:00.')
    hours,minutes=map(int,offset[1:].split(':'))
    if hours>14 or minutes>59 or (hours==14 and minutes):raise LogInputError('Timezone offset must be within ±14:00.')
    if type(failure_threshold) is not int or not 2<=failure_threshold<=100:raise LogInputError('Failure threshold must be 2–100 records.')
    if type(failure_minutes) is not int or not 1<=failure_minutes<=60:raise LogInputError('Failure window must be 1–60 minutes.')
    tz=timezone(timedelta(minutes=(hours*60+minutes)*(1 if offset[0]=='+' else -1)))
    return {'year':year,'naive_timestamp_offset':offset,'failure_threshold':failure_threshold,'failure_window_minutes':failure_minutes,
            'distinct_user_threshold':5,'distinct_source_threshold':3,'diversity_window_minutes':10,
            'success_prior_failure_threshold':3,'success_window_minutes':10},tz


def timestamp(value,settings,tz):
    assumed_year=False
    try:
        if re.match(r'^[A-Z][a-z]{2}\s',value):
            month,day,clock=value.split();h,m,s=map(int,clock.split(':'))
            dt=datetime(settings['year'],MONTHS[month],int(day),h,m,s);assumed_year=True
        else:
            if not re.match(r'^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d',value):raise ValueError()
            dt=datetime.fromisoformat(value.replace('Z','+00:00'))
        assumed_offset=dt.tzinfo is None
        if assumed_offset:dt=dt.replace(tzinfo=tz)
        return dt.astimezone(timezone.utc),assumed_year,assumed_offset
    except (ValueError,KeyError,OverflowError):raise LogInputError('Invalid or unsupported timestamp.') from None


def event_record(ts,event,user,source,host,service,line,settings,tz,invalid_user=False):
    user=identifier(user,'username',128);host=identifier(host,'host');service=identifier(service,'service',64)
    try:source=str(ipaddress.ip_address(source.strip()))
    except (ValueError,AttributeError):raise LogInputError('Source IP is missing or invalid.') from None
    dt,year_assumed,offset_assumed=timestamp(ts,settings,tz)
    return {'time':dt,'timestamp_utc':dt.isoformat(),'event':event,'username':user,'source_ip':source,
            'host':host,'service':service,'source_line':line,'invalid_user':invalid_user,
            'year_assumed':year_assumed,'offset_assumed':offset_assumed}


def parse(data,mode,settings,tz):
    if not isinstance(data,bytes) or not 0<len(data)<=MAX_BYTES:raise LogInputError('Choose a nonempty UTF-8 file up to 5 MiB.')
    try:text=data.decode('utf-8-sig')
    except UnicodeError:raise LogInputError('File must be UTF-8 text. Binary EVTX files are not supported.') from None
    if '\x00' in text:raise LogInputError('Binary/NUL-containing input is not supported.')
    lines=text.splitlines()
    if len(lines)>MAX_RECORDS+1:raise LogInputError('File exceeds the 20,000-line limit.')
    if not isinstance(mode,str) or mode not in {'auto','openssh','csv'}:raise LogInputError('Select auto, openssh or csv format.')
    first=next((x for x in lines if x.strip()),'')
    if not first:raise LogInputError('File contains no nonblank records.')
    if mode=='auto':mode='csv' if ',' in first and any(k in first.lower() for k in ('timestamp','source_ip','event,')) else 'openssh'
    records=[];diagnostics=[];counts=Counter()
    def rejected(line,reason,kind='invalid'):
        counts[kind]+=1
        if len(diagnostics)<50:diagnostics.append({'line':line,'kind':kind,'reason':reason})
    if mode=='csv':
        csv.field_size_limit(8192)
        reader=csv.reader(io.StringIO(text),strict=True)
        try:
            headers=next(reader)
            while not headers or not any(h.strip() for h in headers):headers=next(reader)
            headers=[h.strip().lower() for h in headers]
            if len(headers)!=len(set(headers)) or not {'timestamp','event','username','source_ip','host'}.issubset(headers):
                raise LogInputError('CSV requires unique timestamp,event,username,source_ip,host headers; service is optional.')
            previous=reader.line_num
            for row in reader:
                line=previous+1;previous=reader.line_num
                if not row or not any(c.strip() for c in row):continue
                counts['input_records']+=1
                try:
                    if len(row)!=len(headers):raise LogInputError('CSV row field count differs from header.')
                    item=dict(zip(headers,row));outcome=item['event'].strip().lower()
                    if outcome not in {'success','failure','4624','4625'}:raise LogInputError('Event must be success/failure or normalized 4624/4625.')
                    outcome='success' if outcome in {'success','4624'} else 'failure'
                    records.append(event_record(item['timestamp'].strip(),outcome,item['username'],item['source_ip'],item['host'],item.get('service','auth'),line,settings,tz))
                except LogInputError as exc:rejected(line,str(exc))
        except csv.Error:raise LogInputError('CSV quoting or field size is invalid; use the documented schema.') from None
    else:
        for line_number,line in enumerate(lines,1):
            if not line.strip():continue
            counts['input_records']+=1
            if len(line)>8192:rejected(line_number,'Log line exceeds 8192 characters.');continue
            prefix=PREFIX.match(line)
            if not prefix:
                rejected(line_number,'Unsupported line prefix or non-OpenSSH record.','ignored');continue
            auth=AUTH.match(prefix['msg'])
            if not auth:
                rejected(line_number,'Auxiliary or unsupported SSH message; not counted as an authentication result.','ignored');continue
            try:
                records.append(event_record(prefix['ts'],'failure' if auth['outcome']=='Failed' else 'success',auth['user'],auth['ip'],prefix['host'],'sshd',line_number,settings,tz,bool(auth['invalid'])))
            except LogInputError as exc:rejected(line_number,str(exc))
    if counts['input_records']>MAX_RECORDS:raise LogInputError('At most 20,000 records are supported.')
    counts['parsed_events']=len(records)
    return records,mode,dict(counts),diagnostics


def peak_window(events,seconds,distinct=None):
    left=0;counter=Counter();best=(-1,0,0,0)
    for right,event in enumerate(events):
        if distinct:counter[event[distinct]]+=1
        while (event['time']-events[left]['time']).total_seconds()>seconds:
            if distinct:
                value=events[left][distinct];counter[value]-=1
                if not counter[value]:del counter[value]
            left+=1
        metric=len(counter) if distinct else right-left+1
        if (metric,right-left+1)>(best[0],best[3]):best=(metric,left,right+1,right-left+1)
    return best[0],events[best[1]:best[2]]


def evidence(events):
    return {'first_event_utc':events[0]['timestamp_utc'],'last_event_utc':events[-1]['timestamp_utc'],
            'record_count':len(events),'source_lines':[e['source_line'] for e in events[:20]],
            'line_references_truncated':len(events)>20}


def detect(records,settings):
    failures=defaultdict(list);by_user=defaultdict(list);all_groups=defaultdict(list)
    for e in records:
        all_groups[(e['host'],e['service'],e['source_ip'],e['username'])].append(e)
        if e['event']=='failure':
            failures[(e['host'],e['service'],e['source_ip'])].append(e)
            by_user[(e['host'],e['service'],e['username'])].append(e)
    alerts=[]
    def add(rule,title,scope,window,threshold,metric,events,meaning,extra=None):
        item={'rule':rule,'title':title,'priority':'review','scope':scope,'window_minutes':window,
              'threshold':threshold,'observed_metric':metric,'evidence':evidence(events),
              'meaning':meaning,'suggested_action':'Check expected user activity, shared gateways, service automation, clock accuracy and duplicate/forwarded records; correlate with additional logs before acting.'}
        if extra:item.update(extra)
        alerts.append(item)
    for (host,service,source),events in failures.items():
        scope={'host':host,'service':service,'source_ip':source}
        count,window=peak_window(events,settings['failure_window_minutes']*60)
        if count>=settings['failure_threshold']:
            add('SLA-001','Repeated failures from one source',scope,settings['failure_window_minutes'],settings['failure_threshold'],count,window,
                'The failure-record threshold was reached. This may indicate repeated guessing, user mistakes or automation; unique connection attempts were not verified.')
        count,window=peak_window(events,600,'username')
        if count>=5:
            add('SLA-002','One source failing across multiple usernames',scope,10,5,count,window,
                'A source reached the distinct-username threshold. This can resemble broad guessing or spraying; passwords and attacker intent are not visible.',
                {'username_examples':list(dict.fromkeys(e['username'] for e in window))[:10]})
    for (host,service,user),events in by_user.items():
        count,window=peak_window(events,600,'source_ip')
        if count>=3:
            add('SLA-003','One username failing from multiple sources',{'host':host,'service':service,'username':user},10,3,count,window,
                'Distinct logged source IPs reached the threshold. Distributed guessing, legitimate devices and network changes can share this pattern.',
                {'source_ip_examples':list(dict.fromkeys(e['source_ip'] for e in window))[:10]})
    for (host,service,source,user),events in all_groups.items():
        queue=deque();best=None
        # Evaluate successes before adding failures at the same timestamp.
        for dt,group in itertools.groupby(events,key=lambda e:e['time']):
            group=list(group)
            while queue and (dt-queue[0]['time']).total_seconds()>600:queue.popleft()
            for success in (e for e in group if e['event']=='success'):
                if len(queue)>=3 and (best is None or len(queue)>best[0]):
                    best=(len(queue),list(itertools.islice(queue,20)),queue[0],queue[-1],success)
            queue.extend(e for e in group if e['event']=='failure')
        if best:
            count,examples,first,last,success=best
            add('SLA-004','Success after repeated failures',{'host':host,'service':service,'source_ip':source,'username':user},10,3,count,[first,success],
                'A success followed at least three strictly earlier failures for the same host/service/source/user key. This does not establish that the successful logon was unauthorized.',
                {'evidence':{'first_event_utc':first['timestamp_utc'],'last_event_utc':success['timestamp_utc'],
                             'prior_failure_count':count,'failure_line_examples':[e['source_line'] for e in examples],
                             'line_references_truncated':count>20,'success_line':success['source_line']}})
    alerts.sort(key=lambda a:(a['evidence']['first_event_utc'],a['rule'],json.dumps(a['scope'],sort_keys=True)))
    for i,a in enumerate(alerts,1):a['id']=f'ALERT-{i:04d}'
    return alerts


def analyze(data,filename='uploaded.log',mode='auto',year=2026,offset='+00:00',failure_threshold=5,failure_minutes=5):
    settings,tz=config(year,offset,failure_threshold,failure_minutes)
    records,mode,counts,diagnostics=parse(data,mode,settings,tz)
    ordered=all(records[i]['time']<=records[i+1]['time'] for i in range(len(records)-1))
    records.sort(key=lambda e:(e['time'],e['source_line']))
    duplicates=len(records)-len({(e['timestamp_utc'],e['event'],e['username'],e['source_ip'],e['host'],e['service']) for e in records})
    alerts=detect(records,settings)
    warnings=[]
    if not ordered:warnings.append('Input timestamps were out of order; records were sorted. Confirm year, timezone and clock accuracy.')
    if any(e['year_assumed'] for e in records):warnings.append('Yearless syslog timestamps use the selected log year. Multi-year logs and Dec/Jan rollover are not inferred; split or normalize them first.')
    if any(e['offset_assumed'] for e in records):warnings.append('Naive timestamps use the selected fixed UTC offset. Confirm the offset for these logs, including daylight-saving changes.')
    if counts.get('invalid',0) or counts.get('ignored',0):warnings.append('Some input records were invalid or unsupported. Review parsing diagnostics before drawing conclusions.')
    if duplicates:warnings.append('Identical normalized records were found and counted. Review possible forwarding or rotation duplicates before interpreting alerts.')
    status='no_supported_events' if not records else 'partial' if counts.get('invalid',0) or counts.get('ignored',0) else 'parsed'
    preview=[{k:v for k,v in e.items() if k not in {'time'}} for e in records[:200]]
    return {'tool':'Security Log Analyzer','version':VERSION,'report_id':str(uuid.uuid4()),'analyzed_at_utc':datetime.now(timezone.utc).isoformat(),
      'source_file':str(filename).replace('\\','/').split('/')[-1][:255],'input_sha256':hashlib.sha256(data).hexdigest(),
      'format':mode,'parse_status':status,'settings':settings,
      'summary':{'input_records':counts.get('input_records',0),'parsed_events':len(records),
        'failures':sum(e['event']=='failure' for e in records),'successes':sum(e['event']=='success' for e in records),
        'ignored_records':counts.get('ignored',0),'invalid_records':counts.get('invalid',0),
        'identical_normalized_records':duplicates,'alerts':len(alerts),'returned_alerts':min(len(alerts),200),
        'omitted_alerts':max(0,len(alerts)-200),'year_assumed_records':sum(e['year_assumed'] for e in records),
        'offset_assumed_records':sum(e['offset_assumed'] for e in records)},
      'time_range_utc':{'first':records[0]['timestamp_utc'] if records else None,'last':records[-1]['timestamp_utc'] if records else None},
      'alerts':alerts[:200],'rule_counts':dict(Counter(a['rule'] for a in alerts)),
      'top_failure_sources':[{'source_ip':k,'failure_records':v} for k,v in Counter(e['source_ip'] for e in records if e['event']=='failure').most_common(10)],
      'events_preview':preview,'preview_truncated':len(records)>200,'diagnostics':diagnostics,
      'diagnostics_truncated':counts.get('invalid',0)+counts.get('ignored',0)>50,'warnings':warnings,'limitations':LIMITATIONS}


def csv_safe(value):
    value=str(value)
    return "'"+value if value.lstrip().startswith(('=','+','-','@')) or value.startswith(('\t','\r','\n')) else value


def to_csv(report):
    stream=io.StringIO(newline='');writer=csv.writer(stream)
    writer.writerow(['alert_id','rule','title','host','service','source_ip','username','window_minutes','threshold','observed_metric','first_utc','last_utc','evidence'])
    for a in report['alerts']:
        scope=a['scope'];ev=a['evidence']
        writer.writerow([csv_safe(v) for v in [a['id'],a['rule'],a['title'],scope['host'],scope['service'],scope.get('source_ip',''),scope.get('username',''),a['window_minutes'],a['threshold'],a['observed_metric'],ev['first_event_utc'],ev['last_event_utc'],json.dumps(ev)]])
    return stream.getvalue()


def main():
    p=argparse.ArgumentParser(description='Analyze supported authentication logs locally.')
    p.add_argument('file',type=Path);p.add_argument('--format',choices=['auto','openssh','csv'],default='auto')
    p.add_argument('--year',type=int,default=2026);p.add_argument('--offset',default='+00:00')
    p.add_argument('--threshold',type=int,default=5);p.add_argument('--window',type=int,default=5)
    p.add_argument('--out',type=Path);p.add_argument('--csv',type=Path)
    a=p.parse_args()
    try:
        if a.file.stat().st_size>MAX_BYTES:raise LogInputError('File exceeds 5 MiB.')
        report=analyze(a.file.read_bytes(),a.file.name,a.format,a.year,a.offset,a.threshold,a.window)
        for path,text in ((a.out,json.dumps(report,indent=2)),(a.csv,to_csv(report))):
            if path:path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text,encoding='utf-8')
    except (OSError,ValueError) as exc:p.exit(2,str(exc)+'\n')
    print(report['parse_status'],json.dumps(report['summary']))
    for alert in report['alerts']:print(alert['id'],alert['rule'],alert['title'],json.dumps(alert['scope']))
    return 0 if report['parse_status']=='parsed' else 1

if __name__=='__main__':raise SystemExit(main())
