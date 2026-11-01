#!/usr/bin/env python3
"""Tier 1 passive website security monitor. Python 3.10+, stdlib only."""
import argparse
import datetime as dt
import http.client
import json
import pathlib
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

HEADERS = ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy']
DEFAULT_TARGETS = ['github.com', 'badssl.com', 'expired.badssl.com', 'self-signed.badssl.com', 'wrong.host.badssl.com']
TIMEOUT = 8

def request(url, verify=True):
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPHandler(), NoRedirect())
    req = urllib.request.Request(url, headers={'User-Agent':'Tier1SecurityMonitor/1.0'}, method='HEAD')
    try:
        resp = opener.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as exc:
        resp = exc
    except Exception as exc:
        return {'error': f'{type(exc).__name__}: {exc}'}
    with resp:
        return {'status': resp.status, 'headers': dict(resp.headers.items()), 'location': resp.headers.get('Location')}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def certificate(host):
    out = {'valid': False}
    try:
        with socket.create_connection((host,443), timeout=TIMEOUT) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as conn:
                cert = conn.getpeercert()
                end = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), tz=dt.timezone.utc)
                out.update(valid=True, expires_utc=end.isoformat(), days_remaining=(end-dt.datetime.now(dt.timezone.utc)).days, issuer=str(cert.get('issuer')), subject=str(cert.get('subject')), negotiated_tls=conn.version(), negotiated_cipher=conn.cipher()[0])
    except Exception as exc:
        out['error'] = f'{type(exc).__name__}: {exc}'
        # For intentionally invalid certificates, obtain expiry without claiming trust.
        try:
            pem = ssl.get_server_certificate((host,443), timeout=TIMEOUT)
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                f.write(pem); name=f.name
            try:
                info = ssl._ssl._test_decode_cert(name)
                end = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(info['notAfter']), tz=dt.timezone.utc)
                out['unverified_expires_utc'] = end.isoformat()
                out['unverified_days_remaining'] = (end-dt.datetime.now(dt.timezone.utc)).days
            finally: os.unlink(name)
        except Exception as e:
            out['unverified_certificate_error'] = str(e)
    return out

def tls_versions(host):
    versions = {'TLSv1.2':ssl.TLSVersion.TLSv1_2, 'TLSv1.3':ssl.TLSVersion.TLSv1_3}
    result = {}
    for label, version in versions.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version; ctx.maximum_version = version
            with socket.create_connection((host,443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as conn:
                    result[label] = {'accepted':True, 'negotiated_cipher':conn.cipher()[0]}
        except Exception as exc:
            result[label] = {'accepted':False, 'reason':str(exc)}
    return result

def scan(host):
    host = host.strip().lower()
    if '://' in host or '/' in host or not host or any(c.isspace() for c in host):
        raise ValueError('Targets must be hostnames only, e.g. github.com')
    https = request('https://' + host)
    # Only read headers without disabling verification; invalid certs are reported as errors.
    headers = {k.lower():v for k,v in https.get('headers',{}).items()}
    header_status = {h:{'present':h in headers, 'value':headers.get(h)} for h in HEADERS}
    header_status['frame-protection'] = {'present':'x-frame-options' in headers or 'frame-ancestors' in headers.get('content-security-policy','').lower(), 'value':headers.get('x-frame-options') or ('CSP frame-ancestors' if 'frame-ancestors' in headers.get('content-security-policy','').lower() else None)}
    http = request('http://' + host)
    loc = http.get('location')
    redirect = bool(http.get('status') in (301,302,303,307,308) and loc and urllib.parse.urljoin('http://'+host,loc).startswith('https://'))
    cert = certificate(host)
    findings = []
    if 'error' in https: findings.append({'severity':'info','finding':'HTTPS headers could not be verified: '+https['error']})
    else:
        for name, value in header_status.items():
            if not value['present']: findings.append({'severity':'warning','finding':'Missing '+name})
    if not redirect: findings.append({'severity':'warning','finding':'No direct HTTP to HTTPS redirect observed (or HTTP unavailable)'})
    if not cert['valid']: findings.append({'severity':'high','finding':'Certificate validation failed: '+cert.get('error','unknown')})
    if cert.get('valid') and cert['days_remaining'] <= 30: findings.append({'severity':'warning','finding':'Certificate expires in '+str(cert['days_remaining'])+' days'})
    return {'host':host,'scanned_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'https':https,'security_headers':header_status,'certificate':cert,'tls':tls_versions(host),'http':http,'http_to_https_redirect':redirect,'findings':findings}

def main():
    parser = argparse.ArgumentParser(description='Passive Tier 1 website security monitor')
    parser.add_argument('--targets', nargs='+', default=DEFAULT_TARGETS)
    parser.add_argument('--output', default='reports')
    args=parser.parse_args()
    now=dt.datetime.now(dt.timezone.utc)
    data={'generated_utc':now.isoformat(),'scope':'Tier 1 passive external checks','results':[]}
    for host in args.targets:
        try: data['results'].append(scan(host))
        except Exception as exc: data['results'].append({'host':host,'error':str(exc)})
    path=pathlib.Path(args.output); path.mkdir(parents=True,exist_ok=True)
    stamp=now.strftime('%Y%m%dT%H%M%SZ')
    jsonpath=path/f'scan_{stamp}.json'; mdpath=path/f'scan_{stamp}.md'
    jsonpath.write_text(json.dumps(data,indent=2),encoding='utf-8')
    lines=['# Tier 1 Website Security Scan',f'Generated (UTC): {now.isoformat()}','', '| Target | HTTPS | Valid cert | Days remaining | HTTP→HTTPS | Findings |','|---|---|---|---|---|---|']
    for r in data['results']:
        if 'error' in r: lines.append(f"| {r['host']} | Error | — | — | — | {r['error']} |")
        else:
            c=r['certificate']; lines.append(f"| {r['host']} | {r['https'].get('status', 'error')} | {c['valid']} | {c.get('days_remaining','unknown')} | {r['http_to_https_redirect']} | {len(r['findings'])} |")
            lines += ['',f"## {r['host']}",'',f"HTTPS error: {r['https'].get('error','none')}", '', '**Security headers**']
            lines += [f"- {k}: {'Present' if v['present'] else 'Missing'}" for k,v in r['security_headers'].items()]
            lines += ['', '**TLS versions and negotiated ciphers**']
            lines += [f"- {k}: {v}" for k,v in r['tls'].items()]
            lines += ['', '**Findings**']
            lines += [f"- [{f['severity']}] {f['finding']}" for f in r['findings']]
    mdpath.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(f'JSON report: {jsonpath}\nMarkdown report: {mdpath}')

if __name__=='__main__': main()
