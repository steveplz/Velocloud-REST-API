#!/usr/bin/env/python
#
# remote_diag.py
#
# - Puts the specified Edge in live mode
# - Causes it to initiate a remote diagnostic action
# - Polls for action output, dumps result to stdout
# - Exits live mode
#
# Usage : remote_diag.py <test> --params <params> --host <host> --edge <edge> --enterprise <enterprise> [--operator] [--insecure]
#
# Options:
#   test              the diagnostic test to perform, one of:
#                       - PATHS_DUMP
#                       - TRACEROUTE
#                       - CLIENTS_DUMP
#                       - BASIC_PING
#                       - FLUSH_NAT
#                       - RESTART_DNSMASQ
#                       - ROUTE_DUMP
#                       - NAT_DUMP
#                       - VPN_TEST
#                       - ARP_DUMP
#                       - RESET_USB_MODEM
#                       - DNS_TEST
#                       - ROUTE_SELECT
#                       - BW_TEST
#                       - AP_SCAN_DUMP
#                       - FLOW_DUMP
#                       - INTERFACE_STATUS
#                       - FLUSH_FLOWS
#                       - CLEAR_ARP
#                       - HEALTH_REPORT
#                       - NTP_DUMP
#   params            optional, JSON-encoded, test specific-params
#   host              the VCO hostname (e.g. vcoXX-usca1.velocloud.net or 12.34.56.7)
#   -e edge           id of the edge from which to initiate the action
#   -c enterprise     id of the enterprise with ownership of the edge
#   --operator        authenticate as an operator user (defaults to True)
#   --insecure        when passed, tells the client to ignore SSL certificate verifcation errors (e.g. in a
#                     sandbox environment)
#
# Dependencies:
#   - The only library required to use this tool is the Python requests library, which can be installed with pip
#   - VC_USERNAME and VC_PASSWORD must be set as environment variables
#
POLL_SLEEP_INTERVAL = 10 # seconds to sleep between calls to readLiveData
OUTPUT_FILE = 'diag.html' # file to which HTML-formatted output is written

import argparse
import requests
import json
import re
import sys
import time
import os

class ApiException(Exception):
    pass

class VcoClient(object):

    def __init__(self, hostname, verify_ssl=True):
        self._session = requests.Session()
        self._verify_ssl = verify_ssl
        self._root_url = self._get_root_url(hostname)
        self._portal_url = self._root_url + "/portal/"
        self._livepull_url = self._root_url + "/livepull/liveData/"
        self._seqno = 0

    def _get_root_url(self, hostname):
        """
        Translate VCO hostname to a root url for API calls 
        """
        if hostname.startswith("http"):
            re.sub("http(s)?://", "", hostname)
        proto = "https://"
        return proto + hostname

    def authenticate(self, username, password, is_operator=False):
        """
        Authenticate to API - on success, a cookie is stored in the session
        """
        path = "/login/operatorLogin" if is_operator else "/login/enterpriseLogin"
        url = self._root_url + path
        data = { "username": username, "password": password }
        headers = { "Content-Type": "application/json" }
        r = self._session.post(url, headers=headers, data=json.dumps(data),
                               allow_redirects=False, verify=self._verify_ssl)

    def request(self, method, params, ignore_null_properties=False):
        """
        Build and submit a request
        Returns method result as a Python dictionary
        """
        self._seqno += 1
        headers = { "Content-Type": "application/json" }
        method = self._clean_method_name(method)
        payload = { "jsonrpc": "2.0",
                    "id": self._seqno,
                    "method": method,
                    "params": params }

        if method == "liveMode/readLiveData" or method == "liveMode/requestLiveActions":
            url = self._livepull_url
        else:
            url = self._portal_url

        r = self._session.post(url, headers=headers,
                               data=json.dumps(payload), verify=self._verify_ssl)

        kwargs = {}
        if ignore_null_properties:
            kwargs["object_hook"] = self._remove_null_properties
        response_dict = r.json(**kwargs)
        if "error" in response_dict:
            raise ApiException(response_dict["error"]["message"])
        return response_dict["result"]

    def _remove_null_properties(self, data):
        return {k: v for k, v in data.iteritems() if v is not None}

    def _clean_method_name(self, raw_name):
        """
        Ensure method name is properly formatted prior to initiating request
        """
        return raw_name.strip("/")

def get_env_or_abort(var):
    try:
        return os.environ[var]
    except IndexError:
        print "env.%s is not set. Aborting." % s
    sys.exit(-1)

def make_test(name, params):
    return { "name": name,
             "parameters": [params] }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("test", help="diagnostic test to perform")
    parser.add_argument("-p", "--params", dest="test_params", default="{}", help="test-specific params")
    parser.add_argument("--host", default=os.environ.get("VC_HOSTNAME"),
                        help="vco hostname")
    parser.add_argument("-e", "--edge", type=int,
                        help="id of the edge to perform the diagnostic action")
    parser.add_argument("-c", "--enterprise", type=int,
                        help="id of the enterprise with ownership of the specified edge")
    parser.add_argument("--operator", action="store_true", default=False, help="login as operator")
    parser.add_argument("--insecure", action="store_true", help="ignore ssl cert warnings/errors")
    args = parser.parse_args()

    if args.insecure:
        from requests.packages.urllib3.exceptions import (
            InsecureRequestWarning,
            InsecurePlatformWarning,
            SNIMissingWarning
        )
        for warning in ( InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning ):
            requests.packages.urllib3.disable_warnings(warning)

    # Initialize client, authenticate

    client = VcoClient(args.host, verify_ssl=(not args.insecure)) 
    username = get_env_or_abort("VC_USERNAME")
    password = get_env_or_abort("VC_PASSWORD")

    try:
        client.authenticate(username, password, args.operator)
    except Exception as e:
        print "Encountered error while authenticating: " + str(e)
        sys.exit(-1)


    # 1 : Enter live mode

    edge_id = args.edge
    enterprise_id = args.enterprise
    method = "liveMode/enterLiveMode"
    params = { "edgeId": edge_id, "enterpriseId": enterprise_id }

    try:
        entry_result = client.request(method, params)
        token = entry_result["token"]
    except ApiException as e:
        print "Encountered API error in call to %s: %s" % (method, e)
        sys.exit(-1)

    print "Edge %d entered live mode..." % edge_id


    # 2 : Enqueue remote diagnostic edge action

    # test must be one of:
    #  - PATHS_DUMP
    #  - TRACEROUTE
    #  - CLIENTS_DUMP
    #  - BASIC_PING
    #  - FLUSH_NAT
    #  - RESTART_DNSMASQ
    #  - ROUTE_DUMP
    #  - NAT_DUMP
    #  - VPN_TEST
    #  - ARP_DUMP
    #  - RESET_USB_MODEM
    #  - DNS_TEST
    #  - ROUTE_SELECT
    #  - BW_TEST
    #  - AP_SCAN_DUMP
    #  - FLOW_DUMP
    #  - INTERFACE_STATUS
    #  - FLUSH_FLOWS
    #  - CLEAR_ARP
    #  - HEALTH_REPORT
    #  - NTP_DUMP

    test = make_test(args.test, args.test_params)
    action = { "action": "runDiagnostics",
               "parameters": { "tests": [test] } }
    method = "liveMode/requestLiveActions"
    params = { "token": token,
               "actions": [action] }

    try:
        action_result = client.request(method, params)
    except ApiException as e:
        print "Encountered API error in call to %s: %s" % (method, e)
        sys.exit(-1)

    action_key = action_result["actionsRequested"][0]["actionId"] 
    print "Enqueued %s remote diagnostic action" % args.test


    # 3 : Read live data

    method = "liveMode/readLiveData"
    params = { "token": token }

    live_data = None
    action = None
    dump_complete = False
    while not dump_complete:

        time.sleep(POLL_SLEEP_INTERVAL)
        print "Polling readLiveData..."

        # We're looking for a status value greater than 1 as a cue that the remote precedure has 
        # completed.
        #
        # Status enum is:
        #   0: PENDING
        #   1: NOTIFIED (i.e. Edge has ack'ed its receipt of the action)
        #   2: COMPLETE
        #   3: ERROR
        #   4: TIMEDOUT

        try:
            live_data = client.request(method, params, ignore_null_properties=True)
        except ApiException as e:
            print "Encountered API error in call to %s: %s" % (method, e)
            sys.exit(-1)

        all_action_data = live_data.get("data", {}).get("liveAction", {}).get("data", [])
        actions_matching_key = [a for a in all_action_data if a["data"]["actionId"] == action_key]
        if len(actions_matching_key) > 0:
            action = actions_matching_key[0]
            status = action["data"]["status"]
        else:
            status = 0
        dump_complete = status > 1

    if status == 2:
        diag_results = action["data"].get("results", [])
        output = [r for r in diag_results if r["name"] == args.test][0]["results"]["output"]
        with open(OUTPUT_FILE, "w+") as f:
            f.write(output)
            print "Diagnostic result written to " + OUTPUT_FILE
    else:
        print "Diagnostic failed, see dump below for details..."
        print json.dumps(action, sort_keys=True, indent=2)

    # 4 : Exit live mode

    method = "liveMode/exitLiveMode"
    params = { "edgeId": edge_id, "enterpriseId": enterprise_id }

    try:
        exit_result = client.request(method, params)
    except ApiException as e:
        print "Encountered API error in call to %s: %s" % (method, e)
        sys.exit(-1)
    print "Edge %d exited live mode..." % edge_id

if __name__ == "__main__":
    main()
