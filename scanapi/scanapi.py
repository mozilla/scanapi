#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import argparse
import uuid
import time
import csv
import StringIO
import re
import yaml
import json
from flask import Flask, request
from nessrest import ness6rest

class ScanAPIConfig(object):
    def __init__(self):
        self.confpath = None

class ScanAPIParser(object):
    def __init__(self, content):
        self._result = []
        self._content = content
        self._fd = StringIO.StringIO(self._content)
        self._reader = csv.reader(self._fd)
        self._state = {}
        self._entry()

    def _pass_hostinfo(self, entry):
        s = None
        if entry['host'] not in self._state:
            s = {
                    'vulnerabilities': [],
                    'hostname':        None
                    }
        else:
            s = self._state[entry['host']]

        # if the hostname has not been set yet, just default it to the key/target
        # value
        if s['hostname'] == None:
            s['hostname'] = entry['host']

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

        self._state[entry['host']] = s

    def _pass_cve(self, entry):
        if entry['cve'] == '':
            return
        newvuln = {
                'cve':                 entry['cve'],
                'cvss':                entry['cvss'],
                'title':               entry['name'],
                'vulnerable_packages': []
                }

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
                    'target':          k,
                    'vulnerabilities': v['vulnerabilities'],
                    'hostname':        v['hostname']
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
        self._user = cfg.nessususer
        self._pass = cfg.nessuspass
        self._scanner = ness6rest.Scanner(url=self._url, login=self._user, password=self._pass,
                insecure=True)

    def _unique_scan_id(self):
        return 'scanapi-' + str(uuid.uuid4())

    def _scan_tag_id(self):
        self._scanner.action(action='folders', method='get')
        for t in self._scanner.res['folders']:
            if t['name'] == 'CLI':
                return t['id']
        raise Exception('unable to obtain ID for CLI folder')

    def _scan_from_scanid(self, scanid):
        foldertagid = self._scan_tag_id()
        self._scanner.action(action='scans?folder_id=' + str(foldertagid),
                method='get')
        for scan in self._scanner.res['scans']:
            if scan['name'] == scanid:
                return scan
        raise Exception('scan {} not found'.format(scanid))

    def start_scan(self, targets, policy):
        sid = self._unique_scan_id()
        self._scanner.policy_copy(policy, sid)
        self._scanner.scan_add(targets=targets, name=sid)
        scan = self._scan_from_scanid(sid)
        self._scanner.action(action='scans/' + str(scan['id']) + '/launch', method='post')
        return {'scanid': sid}

    def scan_completed(self, scanid):
        scan = self._scan_from_scanid(scanid)
        if scan['status'] == 'completed':
            return True
        return False

    def scan_results(self, scanid):
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
        ret['details'] = ScanAPIParser(content).result()
        return ret

    def get_policies(self, filter_scanapi=False):
        self._scanner.action(action='policies', method='get')
        ret = []
        for p in self._scanner.res['policies']:
            # if filter_scanapi is True, don't add any template copies scanapi creates
            # when it creates a new scan; we only return templates that would be available
            # for use in a scan
            if filter_scanapi:
                if p['name'].startswith('scanapi'):
                    continue
            ret.append({'id': p['id'], 'name': p['name'], 'description': p['description']})
        return ret

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
    if 'url' not in sect or 'username' not in sect or 'password' not in sect:
        raise ValueError('nessus section incomplete')
    cfg.nessusurl = yamlcfg['nessus']['url']
    cfg.nessususer = yamlcfg['nessus']['username']
    cfg.nessuspass = yamlcfg['nessus']['password']

def domain():
    global scanner
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
    app.run()

@app.route('/api/v1/scan/results')
def api_get_scan_results():
    ret = {'completed': False}
    scanid = request.args.get('scanid')
    if not scanner.scan_completed(scanid):
        return json.dumps(ret)
    ret['completed'] = True
    ret['results'] = scanner.scan_results(scanid)
    return json.dumps(ret)

@app.route('/api/v1/scan', methods=['POST'])
def api_post_scan():
    targetlist = request.form['targets']
    # XXX We expect a comma seperated list of hostnames and IP addresses here, should add
    # some validation prior to pushing this to the scanner
    policy = request.form['policy']
    return json.dumps(scanner.start_scan(targetlist, policy))

@app.route('/api/v1/policies')
def api_get_policies():
    return json.dumps(scanner.get_policies(filter_scanapi=True))

@app.route('/api/v1', strict_slashes=False)
def api_root():
    return json.dumps({'status': 'ok'})

if __name__ == '__main__':
    domain()
