#!/usr/bin/env python
#
# hostxref
#		This script is a zeek synthesizer that uses data from a set
#		of zeek files to determine the protocols accessed by a set
#		of external hosts.
#
#		The default behavior is oriented towards checking protocol
#		use based on DNS usage.  A set of zeek logs are checked to
#		see if external DNS requestors have used other protocols
#		as well.
#
#		hostxref cross-references IP addresses between zeek logfiles.
#		It pulls the requestor addresses from a particular zeek log.
#		(The DNS zeek log is used by default.)  With those addresses,
#		all the other listed zeek logs are searched for that address
#		in the originator-host field.  Matching hosts and protocols
#		are displayed.
#
#
#		To Do:
#			- Handle IPv6 addresses better.
#
#			- The sorting of originator hosts in checklogs() is
#                         very simplistic and isn't quite what I'd like to see.
#
#	usage:
#		hostxref [-help | -Version] [-find proto] <log paths>
#
#
# Revision History
#	1.0	Initial revision.					191209
#		Imported from the version 1.3 of the bro-using script.
#
#	Written by Wayne Morrison, 191209.
#

man = """
hostxref		synthesizes data from zeek logs

SYNOPSIS

  hostxref [options] [-find proto] <log paths>

DESCRIPTION

hostxref is a zeek synthesizer that uses zeek log files to determine how
addresses used by one network protocol are also used by other protocols.
The default results consist of the multi-protocol matches, divided first
by originator's subnet, originator's IP address and then by protocol.

The counts of each such match are given.  This is followed by a line for each
match containing the originator's address, the responder's address, and the
zeek-specific unique ID for that connection.  This is then followed by the
total number of matches for that originator address.

hostxref came from the need to see if a DNS request from a particular host
might be related to SMTP traffic from that requestor's subnet.  The script has
been extended to show relations between other protocols that zeek can monitor.
Thus, for example, relations between SSL and SSH traffic, or X509 and NTP
traffic, can be investigated.

hostxref uses one zeek log to select data from other zeek logs.  The default
behavior is oriented towards checking protocol use based on DNS usage, as
described above.  A set of zeek logs are checked to see if external DNS
requestors have used other protocols as well.  An alternate search protocol
may be specified with the -find option.

hostxref cross-references IP addresses between zeek logfiles.  It pulls the
requestor addresses from a particular zeek log, specified by the -find option.
(The DNS zeek log is used by default.)  With those addresses, all the zeek
logs listed on the command line are searched for that address in the
originator-host field.  Matching hosts and protocols are displayed.

The search protocol's log file must be included in the list of log paths.
Without it, hostxref would not know where to find the appropriate log file.

The network address is expected to be an IPv4 address.  If an IPv6 address
is found in a log file, it will be treated as is, rather than having subnet
masking applied to it.

The -originator option restricts the records to be displayed to those that
have the specified originators.  The option is given a list of IPv4 addresses,
and that list is consulted for the addresses to display.

The -responder option restricts the records to be displayed to those that have
the specified responders.  The option is given a list of IPv4 addresses, and
that list is consulted for the addresses to display.

For these tools, a synthesizer is considered to be a tool takes data from
multiple zeek log files.

SPECIFIC DETAILS ABOUT LOG FILES

Most of the zeek log files have fields specifying the originating host and
the responding host.  These usually correspond to the client and server of
a connection.  Some log files have similar fields with different names.
The field names for these log files are handled by hostxref are equated
to the default field names as shown in the following table:

	log file	originating host	responding host
	--------	----------------	---------------
	dhcp.log	client_addr		server_addr
	files.log	tx_hosts		rx_hosts
	all others	id.orig_h		id.resp_h

The conn.log file will not be examined by hostxref.  This file is a summary
of the connections seen by zeek, and the data are reflected in the individual
protocol log files.  For the purposes of hostxref, it is more useful to
examine the protocol log files than conn.log.

OPTIONS

hostxref takes the following options:

	-find proto
		Choose a protocol to use as the basis for searching other
		protocol logs.

		If this option is not given, then "dns" will be used as
		the default.

		If a log filename is given instead of a protocol name
		(e.g., "smtp.log" instead of "smtp"), then the ".log"
		suffix will be dropped and the first part used as the
		protocol name.

	-nozero
		Hosts from the search log that have no matching entries
		in the other log files will not be displayed.

		By default, data from all hosts from the search log will
		be shown.

	-originator
		Specifies a list of host addresses to match to originator
		fields.  Any records whose originator field matches one of
		the addresses in this list will be displayed, while all
		other are skipped.

		This list is a group of comma-separated addresses.  If
		quotes are used on the command line, this argument may
		contain spaces or tabs (in addition to commas) for better
		readability.

	-responder
		Specifies a list of host addresses to match to responder
		fields.  Any records whose responder field matches one of
		the addresses in this list will be displayed, while all
		other are skipped.

		This list is a group of comma-separated addresses.  If
		quotes are used on the command line, this argument may
		contain spaces or tabs (in addition to commas) for better
		readability.

	-verbose
		Display verbose information.

	-Version
		Display the version information for hostxref.

	-help
		Display a help message.

	-man
		Display this man page.

USAGE EXAMPLES

	$ hostxref -find dns http.log dns.log

		The http.log file is examined to find the hosts that
		have made DNS queries that have also made HTTP connections.
		
		All results will be returned.

	$ hostxref http.log dns.log

		Using the default search protocol of DNS, the http.log file
		is examined to find the hosts that have made DNS queries that
		have also made HTTP connections.
		
		All results will be returned.

		This gives the same results as the first example.

	$ hostxref -find dns http.log dns.log smtp.log

		The http.log and smtp.log files are examined to find the
		hosts that have made DNS queries that have also made HTTP
		or SMTP connections.
		
		All results will be returned.

	$ hostxref -find dns -nozero http.log dns.log smtp.log

		The http.log and smtp.log files are examined to find the
		hosts that have made DNS queries that have also made HTTP
		or SMTP connections.

		Only matching results will be returned.  Hosts from the
		dns.log file that have not made HTTP or SMTP connections
		will not be given in the output.

	$ hostxref -find dns -originator 1.2.3.4 http.log dns.log

		The http.log file is examined to find the hosts in the 1.2.3
		subnet that have made DNS queries that have also made HTTP
		connections.

		All results will be returned.

	$ hostxref -find dns -originator 1.2.3.4,8.9.8.9 http.log dns.log

		The http.log file is examined to find the hosts in the 1.2.3
		or 8.9.8 subnets that have made DNS queries that have also
		made HTTP connections.
		
		All results will be returned.

	$ hostxref -find dns -originator "1.2.3.4, 8.9.8.9" http.log dns.log

		The http.log file is examined to find the hosts in the 1.2.3
		or 8.9.8 subnets that have made DNS queries that have also
		made HTTP connections.

		All results will be returned.

		This provides the same results as the previous example.  For
		better readability, the -originator argument is quoted and a
		space follows the comma.

	$ hostxref -find dns -responder "1.2.3.4, 8.9.8.9" http.log dns.log

		The http.log file is examined to find the entries that have
		the 1.2.3.4 and 8.9.8.9 hosts that have responded to DNS
		queries that have also made HTTP connections.

		All results will be returned.

		For better readability, the -originator argument is quoted
		and a space follows the comma.


AUTHOR

Wayne Morrison, Wayne.Morrison@parsons.com

"""



import os
import sys
import argparse
import subprocess

from signal import signal, SIGPIPE, SIG_DFL


#
# Version information.
#
NAME = "hostxref"
VERS = NAME + " version: 1.0"

#------------------------------------------------------------------------
# Option fields.
#	options handled:
#		-verbose		turn on verbose output
#		-help			give usage message and exit
#		-man			give man page and exit
#		-Version		give command version info and exit
#
#		-find protoname		name of protocol at base of search
#		-nozero			don't show hosts without matches
#		-originator addr	originator address to search for
#		-responder addr		responder address to search for
#


#-----------------------------------------------
# Option values.
#

DEFAULT_SEARCH	= 'dns'			# Default search protocol.
searchproto	= ''			# Protocol at base of search.

origaddr	= None			# Originator address to search for.
origaddrs	= None			# List of originator addresses.

respaddr	= None			# Responder address to search for.
respaddrs	= None			# List of responder addresses.

nozero	= False				# Flag to not print nonmatching hosts.

noconn	= True				# Generally speaking, including output
					# from zeek's conn.log doesn't help.
					# True means don't include it.
					# False means include conn.

verbose	= 0				# Verbose flag.

debug	= False				# Debugging flag.

#-----------------------------------------------
# Default values.
#

DEFAULT_SUBNET = '192.168.1'		# Default subnet to examine.
					# (Not currently used.)

ZEEKCUT = "zeek-cut"			# zeek log parser.

MAXSTRLEN = 50				# Maximum length of string to display.

DEFMASKLEN = 24				# Default mask length.

#------------------------------------------------------------------------
#
# Standard indices for various zeek logfiles.
# Additional indices may be added by various plugins.
# These are passed to zeek-cut.
#

#
# Indices to standard zeek log field data.
#
DEF_TS		= 'ts'
DEF_UID		= 'uid'
DEF_ORIGHOST	= 'id.orig_h'
DEF_RESPHOST	= 'id.resp_h'
DEF_ORIGPORT	= 'id.orig_p'
DEF_RESPPORT	= 'id.resp_p'

#
# Indices to the zeek DHCP log field data.
#
DHCP_TS		= 'ts'
DHCP_UID	= 'uids'
DHCP_CLIENT	= 'client_addr'
DHCP_SERVER	= 'server_addr'

#
# Indices to the zeek files log field data.
#
FILES_TS	= 'ts'
FILES_UID	= 'fuid'
FILES_ORIGHOST	= 'tx_hosts'
FILES_RESPHOST	= 'rx_hosts'


#
# Default list of fields to retrieve.
#
default_fields = [
			DEF_TS,
			DEF_UID,
			DEF_ORIGHOST,
			DEF_RESPHOST
		 ]

#
# List of fields to retrieve from a dhcp.log file.
#
dhcp_fields =	 [
			DHCP_TS,
			DHCP_UID,
			DHCP_CLIENT,
			DHCP_SERVER
		 ]

#
# List of fields to retrieve from a files.log file.
#
files_fields =	 [
			FILES_TS,
			FILES_UID,
			FILES_ORIGHOST,
			FILES_RESPHOST
		 ]

#
# List of dummy fields for those files that don't have relevant fields.
#
dummy_fields =	 [
				'',
				'',
				'',
				''
			 ]

fields = {
		'conn'		: default_fields,
		'dns'		: default_fields,
		'http'		: default_fields,
		'radius'	: default_fields,
		'sip'		: default_fields,
		'smtp'		: default_fields,
		'snmp'		: default_fields,
		'ssl'		: default_fields,
		'weird'		: default_fields,

		'dhcp'		: dhcp_fields,
		'files'		: files_fields,

		'packet_filter'	: dummy_fields,
		'x509'		: dummy_fields
	 }


#
# General indices into the *_fields arrays.
#
IND_TS	 = 0
IND_ID	 = 1
IND_ORIG = 2
IND_RESP = 3

#------------------------------------------------------------------------

paths = []				# Paths from command line.

logtypes = {}				# Types of the zeek logfiles.
typelogs = {}				# Zeek logfiles for the protocol types.

prototables = {}			# Data tables for each protocol's log.

subnetmasks = {}			# Cached subnet masks.

#------------------------------------------------------------------------
# Routine:	main()
#
def main():
	"""
	Do everything.
	"""

	selected = []			# Unique originators in a logfile.

	#
	# Don't complain if the user ctrl-C's out.
	#
	signal(SIGPIPE, SIG_DFL)

	#
	# Parse the command-line arguments.
	#
	getopts()

	#
	# Get the log types of the zeek logs given on the command line.
	#
	getlogtypes()

	#
	# Get the data for each protocol log and store in the
	# appropriate protocol table.
	#
	getprotos()

	#
	# Find the unique originators from the appropriate log file.
	#
	selected = selecttargets()

	#
	# Check the log files to see if any remote requestors contacted us
	# and more stuff that will be filled in here later.
	#
	checklogs(selected)

	sys.exit(0)


#------------------------------------------------------------------------
# Routine:	getopts()
#
def getopts():
	"""
	Parse the command line for options.
	"""
	global verbose				# Verbose flag.
	global debug				# Debugging flag.

	global paths				# Paths from command line.
	global searchproto			# Protocol to search for.
	global origaddr				# Selected originator address.
	global origaddrs			# List of originator addresses.
	global respaddr				# Selected responder address.
	global respaddrs			# List of responder addresses.
	global nozero				# -nozero flag.
	global id				# -id flag.

	#
	# Show the usage message and exit if no options were given.
	#
	if(len(sys.argv) == 1):
		usage(1);

	#
	# Show the manpage if the -man option was given.     
	#
	if(len(sys.argv) > 1):
		if((sys.argv[1] == '-man') or (sys.argv[1] == '-manpage')):
			manpage()

	#
	# Build our usage string.
	#
	usagestr = usage(0)

	#
	# Build the options parser.
	#
	ap = argparse.ArgumentParser(usage=usagestr, add_help=False)

	#
	# Add the recognized options.
	#
	ap.add_argument('-verbose', action='store_true')
	ap.add_argument('-Version', action='store_true')
	ap.add_argument('-help',    action='store_true')
	ap.add_argument('-debug',   action='store_true')

	ap.add_argument('-nozero',  action='store_true')
	ap.add_argument('-id',	    action='store_true')

	#
	# These options control certain parameters for this script.
	#
	ap.add_argument('-find',  default=DEFAULT_SEARCH)
	ap.add_argument('-originator')
	ap.add_argument('-responder')

	#
	# Now parse the options.
	#
	(args, paths) = ap.parse_known_args()

	#
	# Check for some immediate options.
	#
	if(args.Version):		version()
	if(args.help):			usage(1)
	if(args.verbose):		verbose	= 1
	if(args.debug):			debug	= True
	if(args.nozero):		nozero	= True

	#
	# Get shorthand holders for some options.
	#
	searchproto = args.find
	origaddr    = args.originator
	respaddr    = args.responder

	#
	# Strip out all tabs and spaces, and then split the single-string
	# originator address into a list of addresses.
	#
	if(origaddr != None):
		origaddr = origaddr.strip()
		origaddr = origaddr.replace(' ','')
		origaddr = origaddr.replace('\t','')
		origaddrs = origaddr.split(',')

	#
	# Strip out all tabs and spaces, and then split the single-string
	# originator address into a list of addresses.
	#
	if(respaddr != None):
		respaddr = respaddr.strip()
		respaddr = respaddr.replace(' ','')
		respaddr = respaddr.replace('\t','')
		respaddrs = respaddr.split(',')

	#
	# Ensure a protocol name will be used for the protocol, not the
	# name of a protocol logfile.  If a logfile was given, we'll strip
	# off the ".log" suffix and use the remainder as the protocol name.
	#
	sp = searchproto
	if(sp.endswith(".log") == True):
		searchproto = searchproto.replace(".log","")
		print "logfile \"%s\" given, not a protocol name; using \"%s for search protocol\"\n" % (sp, searchproto)

	#
	# The verbose flag tells us to display the option values.
	#
	if(verbose):
		print "options:"
		print "\tsearch protocol    - \"%s\"" % searchproto

		if(origaddr == None):
			print "\toriginator address - (none)"
		else:
			print "\toriginator addresses:"
			for oa in origaddrs:
				print "\t\t%s" % oa

		if(respaddr == None):
			print "\tresponder address - (none)"
		else:
			print "\tresponder addresses:"
			for ra in respaddrs:
				print "\t\t%s" % ra

		print "\n"


#------------------------------------------------------------------------
# Routine:	getlogtypes()
#
def getlogtypes():
	"""
	Fetch the types of a set of zeek log files.
	This type is determined by the value of each file's first #path line.
	"""

	global searchproto		# Protocol used as basis of search.
	global logtypes			# Types of the zeek logfiles.
	global typelogs			# Zeek logfiles for the protocol types.

	#
	# Find the path entry in the named zeek logfiles.
	#
	for path in paths:

		logtype = 'unknown'			# Type of zeek logfile.

		#
		# Including conn.log doesn't help much, so we'll strip it
		# out here.
		#
		if(noconn == True):
			if((path == 'conn') or
			   (path.endswith('/conn.log') == True)):
				if(verbose):
					print "\n\n\n----> skipping <%s>\n\n\n" % path
				continue

		#
		# Find the first #path line in the zeek log and get the
		# line's value.
		#
		try:
			#
			# Open the log file for reading.
			#
			logfd = open(path, 'rU')

			#
			# Find the log's path field and save the type.
			#
			for ln in logfd.readlines():
				if(ln.startswith("#path")):
					atoms = ln.split("\t")
					logtype = atoms[1].strip()

					break

			logfd.close()

		#
		# Handle IOErrors -- most likely a non-existent file.
		#
		except IOError as exc:
			print "%s:  %s" % (exc.strerror, path)
			sys.exit(1);

		#
		# Handle OSErrors -- dunno what this problem was.
		#
		except OSError as exc:
			print(exc.strerror)
			print "unable to get log type from \"%s\"" % path
			sys.exit(1);

		#
		# Save the types and for this log file.
		#
		logtypes[path] = logtype
		typelogs[logtype] = path

	#
	# Ensure that the requested protocol has a log file included.
	#
	if(searchproto not in logtypes.values()):
		print "no files included for protocol \"%s\"; search cannot continue" % searchproto;
		exit(0)


#----------------------------------------------------------------------
# Routine:	getprotos()
#
def getprotos():
	"""
	Get the data fields for each protocol log and store in the
	appropriate protocol table.

	"""

	for logfn in logtypes:

		proto = logtypes[logfn]

		pfields = fields[proto]

		prototables[proto] = getentries(logfn, pfields)

	#
	# Spacer to make verbose output easier to read.
	#
	if(verbose):
		print ""


#------------------------------------------------------------------------
# Routine:	getentries()
#
def getentries(logfn, fields):
	"""
	Get the entries from a zeek log and put them into a list of hashed
	entries.  The keys to the hash are the strings in the fields argument.
	The list is then returned.
	"""

	lines = []				# Contents of the log file.
	fieldlist = []				# Hashed lines.

	#
	# Build the zeek-cut command line we'll need.
	#
	cmdline = [ZEEKCUT]
	cmdline.extend(fields)

	if(verbose):
		print "reading %s" % logfn

	#
	# Get the requested fields from the zeek log.
	#
	try:
		#
		# Open the log file for reading.
		#
		logfd = open(logfn, 'rU')

		#
		# Use zeek-cut to read the required fields from the log.
		#
		bout = subprocess.check_output(cmdline, stdin=logfd)

		logfd.close()

	#
	# Handle OSErrors -- most likely an unrecognized command.
	#
	except OSError as exc:
		print(exc.strerror)
		log(1, "%s failed:  %s" % (ZEEKCUT, exc.strerr))
		sys.exit(1);

	#
	# Handle CalledProcessErrors -- errors with zeek-cut.
	#
	except subprocess.CalledProcessError as exc:
		retcode = exc.returncode;
		print(exc.strerror)
		log(1, "%s errors:  %s" % (ZEEKCUT, exc.strerr))
		sys.exit(retcode);

	#
	# Convert the bytearray into a string, and then split the lines.
	#
	out = bout.decode("utf-8")
	lines = out.splitlines()

	#
	# Parse the output into a list of hashed entries.
	#
	entrylist = parselog(lines, fields)

	return(entrylist)


#----------------------------------------------------------------------
# Routine:	parselog()
#
def parselog(loglines, fields):

	"""
	Parse a subset of a zeek logfile's contents.  Each line's fields are
	put into a hash with the retrieved field names as the key.  Each of
	those hashed entries are appended to a list of hashed entries.
	That list is returned to the caller.
	"""

	zeekcomm = []				# Hashed communications.
	fcnt = len(fields)			# Number of fields in output.

	#
	# Build the list of hashed entries.
	# 
	for ln in loglines:
		entry = {}

		#
		# Remove comment lines and strip off any leading and
		# trailing whitespace.
		#
		ln = ln.strip()
		if(ln == ''):
			continue
		if(ln.startswith('#') == True):
			continue

		#
		# Split the line into its constituent atoms.
		#
		atoms = ln.split("\t")

		#
		# Put the atoms into a hash, keyed off the field.
		#
		for ind in range(fcnt):
			entry[fields[ind]] = atoms[ind]

		#
		# Add the new entry hash to our big list of entry hashes.
		#
		zeekcomm.append(entry)

	return(zeekcomm)


#------------------------------------------------------------------------
# Routine:	selecttargets()
#
def selecttargets():
	"""
	This routine selects a set of target entries from the full
	list of targets.  A list of the selected targets is returned.

	We may sometime want to return the whole entry, but for now
	we're going to just return the list of unique originators.


	The list of indices is selected by:
		- skipping any records that don't match the responder
		  address (if it was specified)
		- skipping any records that don't have a local responder

	For now, we're skipping the check on local responders.
	"""

	indices = []				# Index list to return.

	origs = {}				# Hash or originators.
	resps = {}				# Hash or responders.
	respsubnets = []			# List of responder subnets.

	#
	# Get a shorthand to the entries from the search file.
	#
	searchtab = prototables[searchproto]

	keyts	= fields[searchproto][IND_TS]
	keyorig = fields[searchproto][IND_ORIG]
	keyresp = fields[searchproto][IND_RESP]

	#
	# If a list of responders was given, we'll get the subnets for
	# each of the responders specified.
	#
	if(respaddr != None):
		for ra in respaddrs:
			rsn = subnet(ra, DEFMASKLEN)
			respsubnets.append(rsn)


	for entry in searchtab:

#		print "%s\t%-15s\t%-15s" % (entry[DNS_TS], entry[DNS_ORIGHOST], entry[DNS_RESPHOST])

		orighost = entry[keyorig]
		resphost = entry[keyresp]

		#
		# Bump the counter for the originating host.
		#
		if(origs.has_key(orighost) == False):
			origs[orighost] = 0
		origs[orighost] += 1

		#
		# If a responder-host address was given, we'll check this
		# entry against it.
		#
		if(respaddr != None):
			if(respaddr != resphost):
				if(debug):
					print "-------------> SKIPPING RESP HOST:  <%s>\t\t<%s>" % (orighost, respaddr)
				continue

				if(debug):
					print "-------------> NOT SKIPPING:  %s\t<%s>\t<%s>" % (searchproto, orighost, respaddr)

		#
		# Append this target to our list of selected targets.
		#
		indices.append(entry)


	if(debug == True):
		print ""
		print "originators:"
		for o in origs:
			print "---> origs:  \t%-15s\t\t%d" % (o, origs[o])
		print "\n"

		print "responders:"
		for r in resps:
			print "---> resps: \t%-15s\t%d" % (r, resps[r])
		print "\n"

		print "selected:"
		for i in indices:
			print "---> selct:  ", i
		print "\n"

	#
	# We may sometime want to return the whole entry, but for now
	# we're going to just return the list of unique originators.
	#
	indices = origs.keys()

	#
	# Return the index list to our caller.
	#
	return(indices)


#----------------------------------------------------------------------
# Routine:	subnet()
#
def subnet(netstr, mask):
	"""
	Get the subnet of the given length (mask) from the given
	network (netstr).  The network is expected to be a string.

	Caveats:
		- The network is expected to be an IPv4 address.
		  If an IPv6 address is passed in, it'll be returned as is.

		- Currently, we're only handling masks of 8, 16, 24, and 32.

	The caveats will (hopefully) be fixed RSN.
	"""

	#
	# Use the cached subnet mask if it's there.
	#
	ckey = "%s/%d" % (netstr, mask)
	if(subnetmasks.has_key(ckey) == True):
		return(subnetmasks[ckey])

	#
	# If the address colons any colons, we'll assume it's an IPv6
	# address and just use the whole thing.
	# Otherwise, we'll treat it as an IPv4 address and do the
	# expected masking.
	#
	if(':' in netstr):
		subby = netstr

	else:
		octets = netstr.split('.')

		if(mask == 8):
			subby = "%s" % octets[0]

		elif(mask == 16):
			subby = "%s.%s" % (octets[0], octets[1])

		elif(mask == 24):
			subby = "%s.%s.%s" % (octets[0], octets[1], octets[2])

		elif(mask == 32):
			subby = netstr

		else:
			print "\ninvalid subnet mask - \"%d\"\n" % mask
			os.exit(24)

	subnetmasks[ckey] = subby
#	print "--------------------> <%s>/%d\t\t<%s>" % (netstr, mask, subby)

	return(subby)


#----------------------------------------------------------------------
# Routine:	checklogs()
#
def checklogs(selected):
	"""
	Check the log files to find cross-matches of requestors.
	"""

	total = 0			# Count of all matches across protocols.
	out = ''			# Overall output buffer.
	subnetlist = []			# List of selected subnets.

	#
	# Build a list of selected subnets from the list of selected hosts.
	#
	for selhost in selected:
		selsub = ''		# Selected host's subnet.

		#
		# Get the subnet of this selected host.
		#
		selsub = subnet(selhost, DEFMASKLEN)

		#
		# Append the subnet to our list of selected subnets,
		# but only if it isn't already there.
		#
		if(selsub not in subnetlist):
			subnetlist.append(selsub)


	#
	# Check the log files to see if any requestors contacted us over
	# any of the specified protocols.
	#
	for selsubnet in subnetlist:
		for selhost in sorted(selected):

			origcnt = 0		# Count of matching originators.
			selsub = ''		# Selected host's subnet.
			subout = ''		# Subnet's output buffer.


			#
			# Skip this selected host if the user specified an
			# originator list and this isn't in it.
			#
			if((origaddr != None) and (selhost not in origaddrs)):
				continue

			#
			# Skip this host if it isn't in the current subnet.
			#
			selsub = subnet(selhost, DEFMASKLEN)
			if(selsub != selsubnet):
				continue


			#
			# Initialize this subnet's output buffer.
			#
			subout = "%s originator's subnet %s:\n" % (searchproto, selsubnet)
			subout += "\toriginator %s:\n" % selhost

			#
			# Check each of the protocols we're to examine for
			# originating hosts in the selected subnet.
			#
			for proto in prototables:

				protocnt = 0	# Count of matches in protocol.
				matches = {}	# Addresses of matching
						# originators.
				protout = ''	# Protocol's output buffer.

				#
				# No need to examine our search protocol.
				#
				if(proto == searchproto):
					continue

				#
				# Get the keys for the search table.
				#
				keyts	= fields[proto][IND_TS]
				keyorig = fields[proto][IND_ORIG]
				keyresp = fields[proto][IND_RESP]

				#
				# Get the search table and originator host.
				#
				searchtab = prototables[proto]

				#
				# Check each of the protocol's entries for the
				# originating host matching the selected host.
				#
				for entry in searchtab:

					#
					# Shorthand for entry's originating
					# and responding hosts.
					#
					orighost = entry[keyorig]
					resphost = entry[keyresp]

					#
					# If user specified a set of responder
					# hosts to search for, then we'll skip
					# hosts that aren't in that set.
					#
					if((respaddr != None) and (resphost not in respaddrs)):
						continue

					#
					# Skip this originator if it isn't in
					# the selected subnet.
					#
					if(subnet(orighost, DEFMASKLEN) != selsub):
						continue

					#
					# Initialize the originator's match-
					# count for this protocol.
					#
					if(matches.has_key(orighost) == False):
						matches[orighost] = 0

					#
					# Increment the originator's match-count
					# and the protocol's match-count.
					#
					matches[orighost] += 1
					protocnt += 1

					#
					# Save the info for this match in the
					# protocol output buffer.
					#
					protout += "\t\t\t%-15s    %-15s    %s\n" % (orighost, resphost, entry['uid'])


				#
				# Add the match count and the protocol output
				# buffer to the output buffer.
				# We'll try to handle things nicely for
				# zero, one, and multiple matches.
				#
				if(protocnt == 0):
					if(verbose):
						subout += "\t\t%-15s:  0 matches\n" % proto
				else:
					if(protocnt == 1):
						subout += "\t\t%-15s:  1 match\n" % proto
					else:
						subout += "\t\t%-15s:  %d matches\n" % (proto, protocnt)

					#
					# Add the protocol output buffer and a
					# spacing newline to the output buffer.
					#
					subout += protout
					subout += "\n"

				#
				# Add the protocol match-count to the
				# originator host's match-count.
				#
				origcnt += protocnt


			#
			# Add originator-host's match-count to the total count.
			#
			subout += "\tmatches for %s:  %d\n\n" % (selhost, origcnt)

			#
			# Zap the host output buffer if we didn't find any
			# matches for this host and the user doesn't want
			# to see unmatching hosts.
			#
			if((origcnt == 0) and (nozero == True)):
				subout = ''

			#
			# Add in the output and match count for this host.
			#
			out += subout
			total += origcnt


	#
	# Print all the matching info we've found.
	#
	print out
	print "total matches:  %d" % total


#----------------------------------------------------------------------
# Routine:	old_checklogs()
#
#		This is the original version of checklogs().  It was reworked
#		to the current version because the old version wasn't very
#		clear.  This should be deleted in the fullness of time.
#
def old_checklogs(selected):
	"""
	Check the log files to find cross-matches of requestors.
	"""

	total = 0			# Count of all matches across protocols.
	out = ''			# Overall output buffer.

	#
	# Check the log files to see if any remote requestors contacted us
	# and more stuff that will be filled in here later.
	#
	for selhost in selected:

		origcnt = 0		# Count of matching originators.
		selsub = ''		# Selected host's subnet.
		hostout = ''		# Host's output buffer.


		#
		# Skip this selected host if the user specified an originator
		# list and this isn't in it.
		#
		if((origaddr != None) and (selhost not in origaddrs)):
			continue

		#
		# Get the subnet of this selected host.
		#
		selsub = subnet(selhost, DEFMASKLEN)

		hostout = "originator %s (subnet %s):\n" % (selhost, selsub)

		for proto in prototables:

			protocnt = 0	# Count of matches in protocol.
			matches = {}	# Addresses of matching originators.

			idlist = {}	# List of unique ids.

			#
			# No need to examine our search protocol.
			#
			if(proto == searchproto):
				continue

			#
			# Get the keys for the search table.
			#
			keyts	= fields[proto][IND_TS]
			keyorig = fields[proto][IND_ORIG]
			keyresp = fields[proto][IND_RESP]

			#
			# Get the search table and originator host.
			#
			searchtab = prototables[proto]

			#
			# Check each of the protocol's entries for the
			# originating host matching the selected host.
			for entry in searchtab:

				#
				# Shorthand for entry's originating host.
				#
				orighost = entry[keyorig]
				resphost = entry[keyresp]

				#
				# If the user specified a set of responder
				# hosts to search for, then we'll skip hosts
				# that aren't in that set.
				#
				if((respaddr != None) and (resphost not in respaddrs)):
					continue

#				woof = subnet(orighost, DEFMASKLEN)
#				print "---------> woof <%s>\t\t<%s>" % (woof, selsub)
				print "---------> woof <%s>\t\t<%s>" % (orighost, selsub)
				if(subnet(orighost, DEFMASKLEN) != selsub):
					continue

				#
				# Initialize the originator's match-count
				# for this protocol.
				#
				if(matches.has_key(orighost) == False):
					matches[orighost] = 0

				#
				# Increment the originator's match-count
				# and the protocol's match-count.
				#
				print "%s match:  <%s>" % (orighost, resphost)
				matches[orighost] += 1
				protocnt += 1

#				print "\n--------\nentry - ", entry
				idlist[orighost] = entry['uid'] 


			if(protocnt == 0):
				if(verbose):
					hostout += "\t%-15s:  0 matches\n\n" % proto
			else:
				if(protocnt == 1):
					hostout += "\t%-15s:  1 match\n\n" % proto
				else:
					hostout += "\t%-15s:  %d matches\n\n" % (proto, protocnt)

				for match in matches:
					hostout += "\t\t%-15s\t\t%d\t<%s>\n" % (match, matches[match], idlist[match])

				hostout += "\n"

			#
			# Add the protocol match-count to the originator
			# host's match-count.
			#
			origcnt += protocnt


		#
		# Add the originator-host's match-count to the total count.
		#
		hostout += "\tmatches for %s:  %d\n\n" % (selhost, origcnt)

		#
		# Zap the host output buffer if we didn't find any matches for
		# this host and the user doesn't want to see unmatching hosts.
		#
		if((origcnt == 0) and (nozero == True)):
			hostout = ''

		#
		# Add in the output and match count for this host.
		#
		out += hostout
		total += origcnt

	print out
	print "total matches:  %d" % total


#----------------------------------------------------------------------
# Routine:	version()
#
def version():
	"""
	Print the version number(s) and exit.
	"""
	print(VERS)
	exit(0)


#----------------------------------------------------------------------
# Routine:	usage()
#
def usage(prtflag):
	"""
	Do something with the usage message.

	If the prtflag parameter is non-zero, we'll print and exit.
	If it is zero, we'll just return the string.
	"""

	#
	# Set up our usage string.
	#
	outstr = """hostxref [options]

        where [options] are:

		-find         - base protocol for searching other protocols
		-nozero       - only display matches
		-originator   - specify originator address list to search for
		-responder    - specify responder address list to search for

                -verbose      - give verbose output
                -Version      - show version and exit
                -help         - show usage message
                -man          - show man page
 """

	#
	# Just return the output if we aren't to print the usage string.
	#
	if(prtflag == 0):
		return(outstr)

	#
	# Print the usage string and exit.
	#
	print("usage:  " + outstr.rstrip())
	exit(0)


#----------------------------------------------------------------------
# Routine:	manpage()  
#
def manpage():
	"""
	Print the zeek-log manpage and exit.
	"""

	global man

	print(man)
	sys.exit(0)


#------------------------------------------------------------------------

#
# Do everything.
#
if(__name__ == '__main__'):
	main()
	sys.exit(0)

#------------------------------------------------------------------------

