#!/usr/bin/env python2
# -*- coding: utf-8 -*-
""" FortiSIEM Remediation script : Reboot FortiGate via API
PS: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
Author: FortiSIEM CSE Team
"""

import re
import sys
import os
import json
import tempfile
import requests
import logging
import logging.handlers
import socket
import xml.dom.minidom
from ftntlib import FortiOSREST
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

sys.path.append('/opt/phoenix/data-definition/remediations')
from remediation import HttpRemediation, Logger

#Args
incident_xml=sys.argv[1]
username=sys.argv[2]
password=sys.argv[3]
host_ip=sys.argv[4]
hostname=sys.argv[5]
api_port=sys.argv[6]

#Config
monitored_vdoms={
	'vdom1':{'port2':{'tx':0,'rx':0},'port3':{'tx':0,'rx':0}},
	'vdom2':{'port4':{'tx':0,'rx':0},'port5':{'tx':0,'rx':0}},
	'vdom3':{'port2':{'tx':0,'rx':0},'port5':{'tx':0,'rx':0}},        
}
#
def send_syslog(server,syslog):
	syslogger = logging.getLogger('syslogger')
	syslogger.setLevel(logging.INFO)
	#UDP
	handler = logging.handlers.SysLogHandler(address = (server,514),  socktype=socket.SOCK_DGRAM)
	syslogger.addHandler(handler)
	syslogger.info(syslog)
	syslogger.handlers[0].flush()

def perf_intf_parser(perf_data):
	perf_data=json.loads(perf_data)
	if perf_data['status'] != 'success':
		return None
	bps_rx = list(map(lambda x : x['bps'], perf_data['results']['rx']))
	bps_tx = list(map(lambda x : x['bps'], perf_data['results']['tx']))
	return sum(bps_rx) / len(bps_rx),sum(bps_tx) / len(bps_tx)

def perf_vdom_parser(perf_data):
	bps_rx = [perf_data[port]['rx'] for port in perf_data]
	bps_tx = [perf_data[port]['tx'] for port in perf_data]
	return sum(bps_rx),sum(bps_tx)

class FortiGateRebootRemediation(HttpRemediation):
	def run_remediation(self, args):
		fgt = FortiOSREST()
		#fgt.debug('on')
		fgt.login(self.mAccessIp, self.mPort, self.mUser, self.mPassword)

		for vdom in monitored_vdoms:
			for port in monitored_vdoms[vdom]:
				response = fgt.get('monitor', 'system', 'traffic-history?interface='+port+'&time_period=hour', parameters={'vdom': 'root'})
				monitored_vdoms[vdom][port]['rx'],monitored_vdoms[vdom][port]['tx']=perf_intf_parser(response)
			print(monitored_vdoms[vdom])
			vdom_rx,vdom_tx=perf_vdom_parser(monitored_vdoms[vdom])
			syslog='[PH_DEV_MON_INTF_USAGE_TOTAL]:[eventSeverity]=PHL_INFO,[fileName]=bw_collector.py,[lineNumber]=0,[hostName]='+str(vdom)+',[hostIpAddr]='+str(host_ip)+',[pollIntv]=0,[recvBitsPerSec]='+str(vdom_rx)+',[sentBitsPerSec]='+str(vdom_tx)+',[recvPkts64]=0,[sentPkts64]=0,[phLogDetail]=collected_by_bw_collector'
			print('Sending: ',syslog)
			send_syslog('127.0.0.1',syslog)
			

		#self.log.info("returned by FortiGate:\n%s" % response)
		fgt.logout()
		exit(0)

if __name__ == "__main__":
	remediation = FortiGateRebootRemediation()
	remediation.execute(sys.argv)
