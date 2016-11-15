#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import argparse
import uuid
import time
import csv
from functools import wraps
import StringIO
import re
import ipaddr
import yaml
import json
import warnings
from requests.packages.urllib3 import exceptions as requestexp
from flask import Flask, request, jsonify, abort
from nessrest import ness6rest

class ScanAPIConfig(object):
    def __init__(self):
        self.confpath = None
        self.nessusurl = None
        self.nessusakey = None
        self.nessusskey = None
        self.nessescacert = None
        self.zone = 'scanapi'
        self.appkeys = []

class ScanAPIParser(object):
    def __init__(self, content, hostinfo, mincvss=None):
        self._result = []
        self._content = content
        self._hostinfo = hostinfo
        self._fd = StringIO.StringIO(self._content)
        self._reader = csv.reader(self._fd)
        self._state = {}
        self._mincvss = mincvss
        self._entry()

    def _hostinfo_locator(self, entry):
        for x in self._hostinfo:
            if 'host-fqdn' in x and x['host-fqdn'] == entry['host']:
                return x
            if x['host-ip'] == entry['host']:
                return x
        return None

    def _pass_hostinfo(self, entry):
        s = None
        if entry['host'] not in self._state:
            s = {
                    'vulnerabilities':     [],
                    'hostname':            None,
                    'ipaddress':           None,
                    'os':                  None,
                    'credentialed_checks': False
                    }
        else:
            s = self._state[entry['host']]

        # if the hostname has not been set yet, just default it to the key/target
        # value
        if s['hostname'] == None:
            s['hostname'] = entry['host']

        thishostinfo = self._hostinfo_locator(entry)

        # attempt to determine the ip address; if our target is an ip just use that,
        # otherwise try to locate the ip address using the supplementary host info
        try:
            ipaddr.IPAddress(entry['host'])
            s['ipaddress'] = entry['host']
        except:
            if thishostinfo != None:
                s['ipaddress'] = thishostinfo['host-ip']

        if thishostinfo != None:
            s['os'] = thishostinfo['operating-system']

        # attempt to extract kernel hostname 
        if 'output of \"uname -a\" is' in entry['output']:
            unamestr = entry['output'].replace('\n', ' ')
            m = re.search('output of "uname -a" is : Linux (\S+) ', unamestr)
            if m != None:
                s['hostname'] = m.group(1)
        elif '= Computer name' in entry['output']:
            cnamestr = entry['output'].replace('\n', ' ')
            m = re.search('(\S+)\s+= Computer name', cnamestr)
            if m != None:
                s['hostname'] = m.group(1)

        # flip credentialed checks if we find plugin output indicating the scan
        # included successfully used credentials
        if 'Credentialed checks : yes' in entry['output']:
            s['credentialed_checks'] = True

        self._state[entry['host']] = s

    def _pass_cve(self, entry):
        if entry['cve'] == '':
            return
        newvuln = {
                'cve':                 entry['cve'],
                'cvss':                entry['cvss'],
                'title':               entry['name'],
                'impact':              entry['risk'].lower(),
                'vulnerable_packages': []
                }

        if self._mincvss != None and newvuln['cvss'] < self._mincvss:
            return

        # see if we can pull the vulnerability package names out of the plugin
        # output
        if 'Remote package installed' in entry['output']:
                vulnpkgstr = entry['output'].replace('\n', ' ')
                m = re.findall('Remote package installed : \S+', vulnpkgstr)
                for vpkg in m:
                    newvuln['vulnerable_packages'].append(vpkg.split(':')[1].strip())
        else:
            m = re.search('Path\s+:([^\n]+)', entry['output'])
            if m != None:
                newvuln['vulnerable_packages'].append(m.group(1).strip())

        self._state[entry['host']]['vulnerabilities'].append(newvuln)

    def _build_results(self):
        for k, v in self._state.iteritems():
            newres = {
                    'target':              k,
                    'vulnerabilities':     v['vulnerabilities'],
                    'hostname':            v['hostname'],
                    'ipaddress':           v['ipaddress'],
                    'os':                  v['os'],
                    'credentialed_checks': v['credentialed_checks']
                    }
            self._result.append(newres)

    def _entry(self):
        for row in self._reader:
            if row[0] == 'Plugin ID': # skip headers
                continue
            entry = {
                    'pluginid':    row[0],
                    'cve':         row[1],
                    'cvss':        row[2],
                    'risk':        row[3],
                    'host':        row[4],
                    'protocol':    row[5],
                    'port':        row[6],
                    'name':        row[7],
                    'synopsis':    row[8],
                    'description': row[9],
                    'solution':    row[10],
                    'seealso':     row[11],
                    'output':      row[12]
                    }
            self._pass_hostinfo(entry)
            self._pass_cve(entry)
        self._build_results()

    def result(self):
        return self._result

class ScanAPIScanner(object):
    def __init__(self, cfg):
        self._url = cfg.nessusurl
        self._akey = cfg.nessusakey
        self._skey = cfg.nessusskey
        caoption = ''
        insecure = True
        if cfg.nessuscacert != None:
            caoption = cfg.nessuscacert
            insecure = False
        self._scanner = ness6rest.Scanner(url=self._url, api_akey=self._akey, api_skey=self._skey,
                insecure=insecure, ca_bundle=caoption)

    def _unique_scan_id(self):
        return 'scanapi-' + str(uuid.uuid4())

    def _scan_tag_id(self):
        self._scanner.action(action='folders', method='get')
        for t in self._scanner.res['folders']:
            if t['name'] == 'CLI':
                return t['id']
        raise Exception('unable to obtain ID for CLI folder')

    def _all_scans(self):
        foldertagid = self._scan_tag_id()
        self._scanner.action(action='scans?folder_id=' + str(foldertagid),
                method='get')
        return self._scanner.res['scans']

    def _all_policies(self):
        self._scanner.action(action='policies', method='get')
        return self._scanner.res['policies']

    def _scan_from_scanid(self, scanid):
        scans = self._all_scans()
        if scans == None:
            return None
        for scan in scans:
            if scan['name'] == scanid:
                return scan
        raise Exception('scan {} not found'.format(scanid))

    def _scan_get_hosts(self, scan):
        self._scanner.action(action='scans/' + str(scan['id']), method='get')
        return self._scanner.res['hosts']

    def _scan_host_details(self, scan, host):
        self._scanner.action(action='scans/' + str(scan['id']) + '/hosts/' +
                str(host['host_id']), method='get')
        return self._scanner.res['info']

    def _supplemental_hostinfo(self, scanid):
        scan = self._scan_from_scanid(scanid)
        hosts = self._scan_get_hosts(scan)
        # for each host, gather some information we will merge into the result
        return [self._scan_host_details(scan, x) for x in hosts]

    def start_scan(self, targets, policy):
        sid = self._unique_scan_id()
        self._scanner.policy_copy(policy, sid)
        self._scanner.scan_add(targets=targets, name=sid)
        scan = self._scan_from_scanid(sid)
        self._scanner.action(action='scans/' + str(scan['id']) + '/launch', method='post')
        return {'scanid': sid}

    def scan_completed(self, scanid):
        scan = self._scan_from_scanid(scanid)
        if scan == None:
            return False
        if scan['status'] == 'completed':
            return True
        return False

    def scan_purge(self, olderthan):
        scans_removed = 0
        policies_removed = 0
        removescanids = []
        removepolicyids = []
        now = int(time.time())
        # remove old scans
        scans = self._all_scans()
        if scans != None:
            for scan in scans:
                if scan['last_modification_date'] < (now - olderthan) and \
                    scan['name'].startswith('scanapi'):
                    removescanids.append(scan['id'])
            for scanid in removescanids:
                self._scanner.action(action='scans/' + str(scanid), method='delete')
                scans_removed += 1
        # remove old policies
        policies = self._all_policies()
        if policies != None:
            for policy in policies:
                if policy['last_modification_date'] < (now - olderthan) and \
                    policy['name'].startswith('scanapi'):
                    removepolicyids.append(policy['id'])
            for policyid in removepolicyids:
                self._scanner.action(action='policies/' + str(policyid), method='delete')
                policies_removed += 1
        return {"scans_removed": scans_removed, "policies_removed": policies_removed}

    def scan_results(self, scanid, mincvss=None):
        ret = {}
        scan = self._scan_from_scanid(scanid)
        # export and transform the entire scan result set; use csv output here
        postdata = {'format': 'csv'}
        self._scanner.action(action='scans/' + str(scan['id']) + '/export',
                method='post', extra=postdata)
        fileid = self._scanner.res['file']
        while True:
            self._scanner.action(action='scans/' + str(scan['id']) + '/export/' +
                    str(fileid) + '/status', method='get')
            if self._scanner.res['status'] == 'ready':
                break
            time.sleep(0.5)
        content = self._scanner.action('scans/' + str(scan['id']) + '/export/' +
                str(fileid) + '/download', method='get', download=True)
        hostinfo = self._supplemental_hostinfo(scanid)
        ret['zone'] = cfg.zone
        ret['details'] = ScanAPIParser(content, hostinfo, mincvss=mincvss).result()
        return ret

    def get_policies(self, filter_scanapi=False):
        policies = self._all_policies()
        ret = []
        for p in policies:
            # if filter_scanapi is True, don't add any template copies scanapi creates
            # when it creates a new scan; we only return templates that would be available
            # for use in a scan
            if filter_scanapi:
                if p['name'].startswith('scanapi'):
                    continue
            ret.append({'id': p['id'], 'name': p['name'], 'description': p['description']})
        return ret

class ServiceAPIError(Exception):
    def __init__(self, message, status_code):
        self.message = message
        self.status_code = status_code

    def to_dict(self):
        return {'message': self.message}

app = Flask(__name__)
cfg = ScanAPIConfig()
scanner = None

def load_config(confpath):
    yamlcfg = None
    with open(confpath, 'r') as fd:
        yamlcfg = yaml.load(fd.read())
    if 'nessus' not in yamlcfg:
        raise ValueError('missing nessus section')
    sect = yamlcfg['nessus']
    if 'url' not in sect or 'accesskey' not in sect or 'secretkey' not in sect:
        raise ValueError('nessus section incomplete')
    cfg.nessusurl = yamlcfg['nessus']['url']
    cfg.nessusakey = yamlcfg['nessus']['accesskey']
    cfg.nessusskey = yamlcfg['nessus']['secretkey']
    if 'cacert' in sect:
        cfg.nessuscacert = yamlcfg['nessus']['cacert']
    if 'appkeys' in yamlcfg:
        sect = yamlcfg['appkeys']
        for k, v in sect.iteritems():
            if 'key' not in v:
                raise ValueError('syntax error in appkey entry for {}'.format(k))
            cfg.appkeys.append(v['key'])
    if 'scanapi' in yamlcfg:
        sect = yamlcfg['scanapi']
        if 'zone' in sect:
            cfg.zone = yamlcfg['scanapi']['zone']

def domain():
    global scanner
    warnings.simplefilter('ignore', requestexp.SubjectAltNameWarning)
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', help='specify configuration file',
            metavar='confpath', default='./scanapi.yml', dest='confpath')
    args = parser.parse_args()
    cfg.confpath = args.confpath
    try:
        load_config(cfg.confpath)
    except IOError as e:
        sys.stderr.write('Error loading config file: {}: {}\n'.format(cfg.confpath, e.strerror))
        sys.exit(1)
    except ValueError as e:
        sys.stderr.write('Error parsing config file: {}\n'.format(e))
        sys.exit(1)
    scanner = ScanAPIScanner(cfg)
    if __name__ == '__main__':
        app.run()

def valid_appkey(viewfunc):
    @wraps(viewfunc)
    def decorated(*args, **kwargs):
        appkey = request.headers.get('SCANAPIKEY')
        valid = False
        if len(cfg.appkeys) == 0: # no keys defined, don't require auth
            return viewfunc(*args, **kwargs)
        for key in cfg.appkeys:
            if key == appkey:
                valid = True
                break
        if valid:
            return viewfunc(*args, **kwargs)
        else:
            abort(401)
    return decorated

@app.errorhandler(ServiceAPIError)
def handle_serviceapierror(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

@app.route('/api/v1/scan/results')
@valid_appkey
def api_get_scan_results():
    ret = {'completed': False}
    scanid = request.args.get('scanid')
    mincvss = request.args.get('mincvss')
    if not scanner.scan_completed(scanid):
        return json.dumps(ret)
    ret['completed'] = True
    ret['results'] = scanner.scan_results(scanid, mincvss=mincvss)
    return json.dumps(ret)

@app.route('/api/v1/scan', methods=['POST'])
@valid_appkey
def api_post_scan():
    targetlist = request.form['targets']
    # XXX We expect a comma seperated list of hostnames and IP addresses here, should add
    # some validation prior to pushing this to the scanner
    policy = request.form['policy']
    return json.dumps(scanner.start_scan(targetlist, policy))

@app.route('/api/v1/scan/purge', methods=['DELETE'])
@valid_appkey
def api_scan_purge():
    olderthan = int(request.args.get('olderthan'))
    if olderthan < 300:
        raise ServiceAPIError('olderthan must be >= 300', 400)
    return json.dumps(scanner.scan_purge(olderthan))

@app.route('/api/v1/policies')
@valid_appkey
def api_get_policies():
    return json.dumps(scanner.get_policies(filter_scanapi=True))

@app.route('/api/v1', strict_slashes=False)
def api_root():
    return json.dumps({'status': 'ok'})

domain()
