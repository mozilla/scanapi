#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import argparse
import os
import time
import json
import requests
import warnings
import datetime
import pytz
from requests.packages.urllib3 import exceptions as requestexp
from requests.auth import AuthBase

class ScanAPIAuth(AuthBase):
    def __init__(self, apikey):
        self._apikey = apikey

    def __call__(self, r):
        r.headers['SCANAPIKEY'] = self._apikey
        return r

class ScanAPIRequestor(object):
    def __init__(self, url, key, capath=None):
        self._url = url
        self._key = key
        self._baseurl = url + '/api/v1'
        if capath != None:
            self._verify = capath
        else:
            self._verify = True
        self.body = None

    def _urlfrombase(self, ep):
        return self._baseurl + '/' + ep

    def request(self, ep, method, data=None, params=None):
        if method == 'get':
            r = requests.get(self._urlfrombase(ep), auth=ScanAPIAuth(self._key), params=params,
                    verify=self._verify)
        elif method == 'delete':
            r = requests.delete(self._urlfrombase(ep), auth=ScanAPIAuth(self._key), params=params,
                    verify=self._verify)
        elif method == 'post':
            r = requests.post(self._urlfrombase(ep), auth=ScanAPIAuth(self._key),
                    data=data, verify=self._verify)
        else:
            raise ValueError('invalid request method')
        if r.status_code != requests.codes.ok:
            raise Exception('request failed with status code {}'.format(r.status_code))
        self.body = r.json()

    def purge_scans(self, seconds):
        self.request('scan/purge', 'delete', params={'olderthan': int(seconds)})
        return self.body

    def request_results(self, scanid):
        self.request('scan/results', 'get', params={'scanid': scanid})
        return self.body

    def start_scan(self, targets, policy):
        payload = {'targets': targets, 'policy': policy}
        self.request('scan', 'post', data=payload)
        return self.body

    def request_policies(self):
        self.request('policies', 'get')
        return self.body

class ScanAPIMozDef(object):
    def __init__(self, resp, mozdef_sourcename='scanapi'):
        self._sourcename = mozdef_sourcename
        self._events = [self._parse_result(x) for x in resp['results']['details']]

    def post(self):
        print self._events

    def _parse_result(self, result):
        event = {
                'description': 'scanapi runscan mozdef emitter',
                'sourcename': self._sourcename,
                'utctimestamp':  pytz.timezone('UTC').localize(datetime.datetime.utcnow()).isoformat(),
                'asset': {
                    'hostname': result['hostname']
                    },
                'vulnerabilities': result['vulnerabilities']
                }
        return event

requestor = None

def get_policies():
    resp = requestor.request_policies()
    for x in resp:
        sys.stdout.write('id={} name=\'{}\' description=\'{}\'\n'.format(x['id'],
            x['name'], x['description']))

def get_results(scanid, mozdef=None):
    resp = requestor.request_results(scanid)
    if mozdef == None:
        sys.stdout.write(json.dumps(resp, indent=4) + '\n')
    else:
        mozdef = ScanAPIMozDef(resp)
        mozdef.post()

def purge_scans(seconds):
    sys.stdout.write(json.dumps(requestor.purge_scans(seconds), indent=4) + '\n')

def run_scan(targets, policy, follow=False, mozdef=None):
    # make sure the policy exists
    resp = requestor.request_policies()
    if not policy in [x['name'] for x in resp]:
        sys.stderr.write('Error: policy {} not found\n'.format(policy))
        sys.exit(1)
    # XXX should validate target list
    scanid = requestor.start_scan(targets, policy)['scanid']
    if not follow:
        sys.stdout.write(scanid + '\n')
        return
    while True:
        resp = requestor.request_results(scanid)
        if not resp['completed']:
            time.sleep(10)
            continue
        sys.stdout.write(json.dumps(resp, indent=4) + '\n')
        break

def config_from_env():
    try:
        return {'apiurl': os.environ['SCANAPIURL'], 'apikey': os.environ['SCANAPIKEY']}
    except KeyError as e:
        sys.stderr.write('Error: environment variable {} not found\n'.format(str(e)))
        sys.exit(1)

def domain():
    global requestor
    warnings.simplefilter('ignore', requestexp.SubjectAltNameWarning)
    parser = argparse.ArgumentParser(epilog='The targets parameter can either contain' + \
            ' a comma separated list of targets, or a path to a file containing a target' + \
            ' list. If a file is used, it should contain one target per line.')
    parser.add_argument('--capath', help='path to ca certificate',
            metavar='capath')
    parser.add_argument('--mozdef', help='emit results as vulnerability events to mozdef',
            metavar='mozdefurl')
    parser.add_argument('-s', help='run scan on comma separated targets, can also be filename with targets',
            metavar='targets')
    parser.add_argument('-p', help='policy to use when running scan',
            metavar='policy')
    parser.add_argument('-D', help='purge scans older than argument, must be >= 300',
            metavar='seconds')
    parser.add_argument('-f', help='follow scan until complete and get results',
            action='store_true')
    parser.add_argument('-P', help='list policies', action='store_true')
    parser.add_argument('-r', help='fetch results', metavar='scan id')
    args = parser.parse_args()
    ecfg = config_from_env()
    capath = True # verify parameter for requests, default to enabled
    if args.capath != None:
        capath = args.capath
    requestor = ScanAPIRequestor(ecfg['apiurl'], ecfg['apikey'], capath=capath)
    if args.P:
        get_policies()
    elif args.r != None:
        get_results(args.r, mozdef=args.mozdef)
    elif args.D != None:
        purge_scans(args.D)
    elif args.s != None:
        if args.p == None:
            sys.stderr.write('Error: policy must be specified with -p\n')
            sys.exit(1)
        targets = None
        try:
            # if targets is a file, open it and build a target list
            with open(args.s, 'r') as fd:
                targets = ','.join([x.strip() for x in fd.readlines() if x[0] != '#'])
        except IOError:
            targets = args.s
        run_scan(args.s, args.p, follow=args.f, mozdef=args.mozdef)
    sys.exit(0)

if __name__ == '__main__':
    domain()
