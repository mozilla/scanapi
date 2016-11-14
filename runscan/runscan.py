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
from requests.auth import AuthBase

class ScanAPIAuth(AuthBase):
    def __init__(self, apikey):
        self._apikey = apikey

    def __call__(self, r):
        r.headers['SCANAPIKEY'] = self._apikey
        return r

class ScanAPIRequestor(object):
    def __init__(self, url, key):
        self._url = url
        self._key = key
        self._baseurl = url + '/api/v1'
        self.body = None

    def _urlfrombase(self, ep):
        return self._baseurl + '/' + ep

    def request(self, ep, method, data=None, params=None):
        if method == 'get':
            r = requests.get(self._urlfrombase(ep), auth=ScanAPIAuth(self._key), params=params)
        elif method == 'post':
            r = requests.post(self._urlfrombase(ep), auth=ScanAPIAuth(self._key),
                    data=data)
        else:
            raise ValueError('invalid request method')
        if r.status_code != requests.codes.ok:
            raise Exception('request failed with status code {}'.format(r.status_code))
        self.body = r.json()

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

requestor = None

def get_policies():
    resp = requestor.request_policies()
    for x in resp:
        sys.stdout.write('id={} name=\'{}\' description=\'{}\'\n'.format(x['id'],
            x['name'], x['description']))

def get_results(scanid):
    resp = requestor.request_results(scanid)
    sys.stdout.write(json.dumps(resp, indent=4) + '\n')

def run_scan(targets, policy, follow=False):
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
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', help='run scan on comma separated targets',
            metavar='targets')
    parser.add_argument('-p', help='policy to use when running scan',
            metavar='policy')
    parser.add_argument('-f', help='follow scan until complete and get results',
            action='store_true')
    parser.add_argument('-P', help='list policies', action='store_true')
    parser.add_argument('-r', help='fetch results', metavar='scan id')
    args = parser.parse_args()
    ecfg = config_from_env()
    requestor = ScanAPIRequestor(ecfg['apiurl'], ecfg['apikey'])
    if args.P:
        get_policies()
    elif args.r != None:
        get_results(args.r)
    elif args.s != None:
        if args.p == None:
            sys.stderr.write('Error: policy must be specified with -p\n')
            sys.exit(1)
        run_scan(args.s, args.p, follow=args.f)
    sys.exit(0)

if __name__ == '__main__':
    domain()
