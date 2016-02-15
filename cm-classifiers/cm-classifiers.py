#!/usr/local/bin/python
from commands import getoutput
from pprint import pprint
import re
from prettytable import PrettyTable,PLAIN_COLUMNS
from netaddr import *
from sys import argv, exit
import socket

def print_usage():
	print "Usage: python cm-classifiers.py ip snmp-read-community"


if len(argv) != 3:
	print_usage()
	exit(2)

ip = argv[1]
community = argv[2]

try:
	socket.inet_aton(ip)
except:
	print "Error: invalid ip argument"
	print_usage()
	exit(2)

get_snmpwalk_cmd = lambda oid: "snmpwalk -c %s -v 2c %s %s" % (community, ip, oid)

docsQosParamSetTable = "DOCS-QOS-MIB::docsQosParamSetTable"
docsQosServiceFlowTable = "DOCS-QOS-MIB::docsQosServiceFlowTable"
docsQosServiceFlowStatsTable = "DOCS-QOS-MIB::docsQosServiceFlowStatsTable"
docsQosPktClassTable = "DOCS-QOS-MIB::docsQosPktClassTable"


def process_flows(output, flows={}):
	""" Receives the output of the docsQosServiceFlowTable and returns a dict of flows """
	lines = [l.strip() for l in output.split("\n")]

	for line in lines:
		# Example:
		# DOCS-QOS-MIB::docsQosServiceFlowDirection.2.8948 = INTEGER: upstream(2)
		fields = line.split()

		if len(fields) < 4:
			continue

		oid = fields[0]
		oid_fields = oid.split(".")

		if len(oid_fields) < 3:
			continue

		name = oid_fields[-3].replace("DOCS-QOS-MIB::docsQosServiceFlow","")
		index = oid_fields[-1]
		value_type = { 
			"type": fields[2].replace(":",""),
			"value": " ".join(fields[3:])
		}

		if index in flows:
			flows[index][name] = value_type

		else:
			flows[index] = { name: value_type }

	return flows


def process_flows_paramset(output, flows = {}):
	""" Receives the output of the docsQosParamSetTable and returns a dict of flows """

	flows_lines = [l.strip() for l in output.split("\n") if re.search("\.active", l)]

	for line in flows_lines:
		# Line example: 
		# DOCS-QOS-MIB::docsQosParamSetRequestPolicyOct.2.8955.active = Hex-STRING: 00 00 00 00
		fields = line.split()

		if len(fields) < 4:
			continue

		oid = fields[0]
		oid_fields = oid.split(".")

		if len(oid_fields) < 4:
			continue

		name = oid_fields[-4].replace("DOCS-QOS-MIB::docsQosParamSet","").replace("Traffic","")
		index = oid_fields[-2]
		value_type = { 
			"type": fields[2].replace(":",""),
			"value": " ".join(fields[3:])
		}

		if index in flows:
			flows[index][name] = value_type

		else:
			flows[index] = { name: value_type }

	return flows

def process_flows_stats(output, flows = {}):
	""" Receives the output of the docsQosServiceFlowStatsTable and returns a dict of flows """

	flows_lines = [l.strip() for l in output.split("\n")]

	for line in flows_lines:
		# Line example: 
		# DOCS-QOS-MIB::docsQosServiceFlowPolicedDelayPkts.2.8955 = Counter32: 0
		fields = line.split()

		if len(fields) < 4:
			continue

		oid = fields[0]
		oid_fields = oid.split(".")

		if len(oid_fields) < 3:
			continue

		name = oid_fields[-3].replace("DOCS-QOS-MIB::docsQosServiceFlow","")
		index = oid_fields[-1]
		value_type = { 
			"type": fields[2].replace(":",""),
			"value": " ".join(fields[3:])
		}

		if index in flows:
			flows[index][name] = value_type

		else:
			flows[index] = { name: value_type }

	return flows

def process_classifiers(output):
	""" Receives the output of DOCS-QOS-MIB::docsQosPktClassTable and returns the classifiers"""

	lines = [l.strip() for l in output.split("\n")]

	flows_classifiers = {}
	for line in lines:
		# Example:
		# DOCS-QOS-MIB::docsQosPktClassSourcePortStart.2.8954.5899 = INTEGER: 0
		fields = line.split()

		if len(fields) < 4:
			continue

		oid = fields[0]
		oid_fields = oid.split(".")

		if len(oid_fields) < 4:
			continue

		name = oid_fields[-4].replace("DOCS-QOS-MIB::docsQosPktClass","")
		index = oid_fields[-1]
		flow_index = oid_fields[-2]
		value_type = { 
			"type": fields[2].replace(":",""),
			"value": " ".join(fields[3:])
		}

		if flow_index in flows_classifiers:
			if index in flows_classifiers[flow_index]:
				flows_classifiers[flow_index][index][name] = value_type
			else:
				flows_classifiers[flow_index][index] = { name: value_type }

		else:
			flows_classifiers[flow_index] = {index: { name: value_type } }

	return flows_classifiers

def print_flows(flows):
	"""
	{
		'ActiveTimeout': {'type': 'INTEGER', 'value': '0 seconds'},
		'AdmittedTimeout': {'type': 'INTEGER', 'value': '200 seconds'},
		'BitMap': {'type': 'BITS', 'value': 'C0 00 00 trafficPriority(0) maxTrafficRate(1)'},
		'Direction': {'type': 'INTEGER', 'value': 'downstream(1)'},
		'GrantsPerInterval': {'type': 'INTEGER', 'value': '0'},
		'MaxConcatBurst': {'type': 'INTEGER', 'value': '0'},
		'MaxLatency': {'type': 'Gauge32', 'value': '0 microseconds'},
		'MaxBurst': {'type': 'Gauge32', 'value': '8192'},
		'MaxRate': {'type': 'Gauge32', 'value': '60000000'},
		'MinReservedPkt': {'type': 'INTEGER', 'value': '0'},
		'MinReservedRate': {'type': 'Gauge32', 'value': '0'},
		'NomGrantInterval': {'type': 'Gauge32', 'value': '0 microseconds'},
		'NomPollInterval': {'type': 'Gauge32', 'value': '0 microseconds'},
		'Octets': {'type': 'Counter32', 'value': '0'},
		'PHSUnknowns': {'type': 'Counter32', 'value': '0'},
		'Pkts': {'type': 'Counter32', 'value': '0'},
		'PolicedDelayPkts': {'type': 'Counter32', 'value': '0'},
		'PolicedDropPkts': {'type': 'Counter32', 'value': '0'},
		'Primary': {'type': 'INTEGER', 'value': 'false(2)'},
		'Priority': {'type': 'INTEGER', 'value': '5'},
		'RequestPolicyOct': {'type': 'Hex-STRING', 'value': '00 00 00 00'},
		'SID': {'type': 'Gauge32', 'value': '0'},
		'SchedulingType': {'type': 'INTEGER', 'value': 'undefined(1)'},
		'TimeActive': {'type': 'Counter32', 'value': '701283 seconds'},
		'TimeCreated': {'type': 'Timeticks', 'value': '(6700) 0:01:07.00'},
		'TolGrantJitter': {'type': 'Gauge32', 'value': '0 microseconds'},
		'TolPollJitter': {'type': 'Gauge32', 'value': '0 microseconds'},
		'TosAndMask': {'type': 'Hex-STRING', 'value': 'FF'},
		'TosOrMask': {'type': 'Hex-STRING', 'value': '00'},
		'UnsolicitGrantSize': {'type': 'INTEGER', 'value': '0'}
	}
	"""
	columns = ["Direction", "Primary", "SchedulingType", "MaxRate", "MaxBurst", "Pkts", "Octets" ]
	x = PrettyTable(["ID"] + columns)
	x.align["MaxRate"] = "r"
	x.align["Direction"] = "l"
	x.sortby = "Direction"

	for id,flow in flows.items():
		row = [id] + map(lambda c: flow[c]["value"] if c in flow else "-", columns)
		x.add_row(row)

	print x

def print_flows_classifiers(flows, flows_classifiers):
	"""
	'8955': {
		'5900': {
			'BitMap': {'type': 'BITS','value': 'CC 00 00 rulePriority(0)'},
	       'DestMacAddr': {'type': 'STRING', 'value': '0:0:0:0:0:0'},
	       'DestMacMask': {'type': 'STRING', 'value': '0:0:0:0:0:0'},
	       'DestPortEnd': {'type': 'INTEGER', 'value': '65535'},
	       'DestPortStart': {'type': 'INTEGER', 'value': '0'},
	       'Direction': {'type': 'INTEGER',
	                     'value': 'downstream(1)'},
	       'EnetProtocol': {'type': 'INTEGER', 'value': '0'},
	       'EnetProtocolType': {'type': 'INTEGER',
	                            'value': 'none(0)'},
	       'IpDestAddr': {'type': 'IpAddress', 'value': '0.0.0.0'},
	       'IpDestMask': {'type': 'IpAddress',
	                      'value': '255.255.255.255'},
	       'IpProtocol': {'type': 'INTEGER', 'value': '258'},
	       'IpSourceAddr': {'type': 'IpAddress',
	                        'value': '10.0.0.1212'},
	                        'value': '10.0.0.1'},
	       'IpSourceMask': {'type': 'IpAddress',
	                        'value': '255.255.255.248'},
	       'IpTosHigh': {'type': 'Hex-STRING', 'value': '00'},
	       'IpTosLow': {'type': 'Hex-STRING', 'value': '00'},
	       'IpTosMask': {'type': 'Hex-STRING', 'value': '00'},
	       'Pkts': {'type': 'Counter32', 'value': '0'},
	       'Priority': {'type': 'INTEGER', 'value': '1'},
	       'SourceMacAddr': {'type': 'STRING',
	                         'value': 'ff:ff:ff:ff:ff:ff'},
	       'SourcePortEnd': {'type': 'INTEGER', 'value': '65535'},
	       'SourcePortStart': {'type': 'INTEGER', 'value': '0'},
	       'State': {'type': 'INTEGER', 'value': 'active(1)'},
	       'UserPriHigh': {'type': 'INTEGER', 'value': '7'},
	       'UserPriLow': {'type': 'INTEGER', 'value': '0'},
	       'VlanId': {'type': 'INTEGER', 'value': '0'}}}}
	"""

	flow_columns = ["Direction", "MaxRate"]

	columns = [	
		"IpSourceAddr", 
		"SourcePorts", 
		"IpDestAddr", 
		"IpToS",
		"IpTosMask",
		"DestPorts",
		"Priority",
		"State",
	]

	all_columns = flow_columns + columns
	x = PrettyTable(all_columns)
	x.align["IpSourceAddr"] = "l"
	x.align["IpDestAddr"] = "l"
	x.align["Direction"] = "l"
	x.align["MaxRate"] = "r"
	x.sortby = "Direction"
	for flow_id,classifiers in flows_classifiers.items():

		for classifier_id, params in classifiers.items():
			# Add flow info
			row = map(lambda c: flows[flow_id][c]["value"] if c in flows[flow_id] else "-", flow_columns)
			# Add classifier info
			row += map(lambda c: params[c]["value"] if c in params else "-", columns)

			x.add_row(row)

	print x


# Service Flows
output = getoutput(get_snmpwalk_cmd(docsQosServiceFlowTable))
flows = process_flows(output)

# Param Set
output = getoutput(get_snmpwalk_cmd(docsQosParamSetTable))
flows = process_flows_paramset(output, flows)

# Stats
output = getoutput(get_snmpwalk_cmd(docsQosServiceFlowStatsTable))
flows = process_flows_stats(output, flows)

# Flows Decorators
for id,flow in flows.items():

	# MaxTrafficRate
	if "MaxTrafficRate" in flow:
		val = float(flow["MaxTrafficRate"]["value"])
		if val >= 10**6:
			val = "%.1f M" % (float(val/1000000.0))
			flow["MaxTrafficRate"]["value"] = val
		elif val >= 10**3:
			val = "%.1f K" % (float(val/1000.0))
			flow["MaxTrafficRate"]["value"] = val

	# Direction
	if "Direction" in flow:
		flow["Direction"]["value"] = re.sub("[stream|(|)|1-2]","",flow["Direction"]["value"])

	# Primary
	if "Primary" in flow and flow["Primary"]["value"] == "true(1)":
		flow["Direction"]["value"] = "*" + flow["Direction"]["value"]

	# Remove '(1)' or '(2)' or ....
	for param_name,param_value in flow.items():
			param_value["value"] = re.sub("\([1-9]\)","",param_value["value"])


# CLassifiers
flows_classifiers = process_classifiers(getoutput(get_snmpwalk_cmd(docsQosPktClassTable)))

# Classifiers decorators
for flowid, classifiers in flows_classifiers.items():
	for classifier_id, params in classifiers.items():

		# Source Address
		if "IpSourceAddr" in params and "IpSourceMask" in params:
			network = IPNetwork("%s/%s" % (params["IpSourceAddr"]["value"], params["IpSourceMask"]["value"]))
			params["IpSourceAddr"]["value"] = "%s/%d" % (params["IpSourceAddr"]["value"], network.prefixlen)

		# Destination Address
		if "IpDestAddr" in params and "IpDestMask" in params:
			network = IPNetwork("%s/%s" % (params["IpDestAddr"]["value"], params["IpDestMask"]["value"]))
			params["IpDestAddr"]["value"] = "%s/%d" % (params["IpDestAddr"]["value"], network.prefixlen)


		# Source Ports
		if "SourcePortStart" in params and "SourcePortEnd" in params:
			params["SourcePorts"] = { 
				"value": "%s:%s" % (params["SourcePortStart"]["value"],params["SourcePortEnd"]["value"]) 
			}

		# Destination Ports
		if "DestPortStart" in params and "DestPortEnd" in params:
			params["DestPorts"] = { 
				"value": "%s:%s" % (params["DestPortStart"]["value"],params["DestPortEnd"]["value"]) 
			}	

		# ToS
		if "IpTosHigh" in params and "IpTosLow" in params:
			params["IpToS"] = {
				"value": "%s:%s" % (params["IpTosLow"]["value"], params["IpTosHigh"]["value"])
			}

		# Remove '(1)' or '(2)' or ....
		for param_name,param_value in params.items():
			param_value["value"] = re.sub("\([1-9]\)","",param_value["value"])



print "> Service Flows:"
print_flows(flows)

print "\n> Classifiers:"
print_flows_classifiers(flows, flows_classifiers)


