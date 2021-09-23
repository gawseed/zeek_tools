#!/usr/bin/env python
#
# zeek-grep
#	This script searches fields of a zeek log file for a specified term.
#	The search term will be looked for in given fields of the log file.
#
#
#	todo:
#
#		- implement the -h option
#
#		- implement the -cs option
#
#		- only display metadata for files that have matching entries
#
#		- implement the -nilter option
#
#		- implement the "any" special field name in filters
#
#	examples for future options:
#
#		zeek-grep -nilter query=example.com		logfiles
#			show entries that don't have a query that is
#			exactly "example.com"
#
#		zeek-grep -nilter query=/example			logfiles
#			show entries that don't have a query that contains
#			"example"
#
#		zeek-grep -nilter rcode=^2			logfiles
#			show entries that don't have an rcode that starts
#			with 2
#
#		zeek-grep -nilter query=$.com			logfiles
#			show entries that don't have a query that ends with
#			".com"
#
#		zeek-grep -cs ...
#			query searches will be case-sensitive; by default
#			searches are case-insensitive
#
#		zeek-grep -out=id.resp_h,id.orig_h,query,response	logfiles
#			specify the fields from matching (non-matching) entries
#			to be displayed; by default, all fields will be shown
#
#		(Caveat:  -nilter, -c, and -out are still TBD.)
#
#
#	usage:
#		zeek-grep [-filter term] [-and] [-cs] [-h] [-meta] <log paths>
#
#
# Revision History
#	1.0	Initial revision.				200210
#		Ported from bro-grep.py v1.1.
#
#	Written by Wayne Morrison, 200210.
#

man = """
zeek-grep		field-based searching in zeek logs

SYNOPSIS

  zeek-grep [options] [-find proto] <log paths>

DESCRIPTION

zeek-grep searches zeek log files for data in specified fields.  This allows
narrow searching in specific areas, rather than broad searches that don't
recognize the log fields.  Regular grep will find matches anywhere in the
line; zeek-grep narrows the searching to specific data fields.

The user must specify one or more filters, using the -filter option, which
are used for selecting records from the log files.  A filter contains a log
field name, a search value.  the log field is checked for an exact match to
the search value.  (A case-insensitive match, that is.) A little refinement
to the search may be made by including one of several optional modifiers.

Filter arguments look like this:  "field=search".  The optional search
modifiers are included immediately after the equals sign.  The filter
fields are described below.

	- The log field name is the name of a field in a zeek log file.
	  Examples:
		id.orig_h, id.resp_h		used in many zeek logs
		qclass				dns.log
		mailfrom			smtp.log

	- The search value is the value to be searched for in the associated
	  field name.  Reasonable values are completely dependent on the
	  log field.  The search values are checked with case-insensitive
	  comparisons.

	- An optional search modifier provides a little regular-expression
	  type of search modification.  The modifier must be given immediately
	  after the equals-sign in the filter definition.
	  The valid modifiers are:

		^	the search value must be at the beginning of the field

		$	the search value must be at the end of the field

		/	the search value may be anywhere within the field

Multiple filters may be used in a single execution of zeek-grep.  The results
of these filters are logically OR'd.  This means that if any filter succeeds
for an entry, that entry will be displayed.  The results of all filters may
be logically AND'd if the -and option is used.

The USAGE EXAMPLES section below contains several examples of filters.

Multiple zeek log files may be specified for searching.  The files may be of
differing types.  If a filter names a field not recorded in a particular log
file, the field will be skipped for that file.

OPTIONS

zeek-grep takes the following options:

	-filter <filter definition>
		A field and value pair that defines a search of a set of
		zeek log files.  An optional search modifier may also be
		included in the filter definition.

		Multiple filters may be defined for a single execution of
		zeek-grep.

	-and
		Logically AND the filter results, instead of using the
		default logical OR.

	-meta
		The metadata from the zeek log file will be printed.

	-h
		The filename of the zeek log file will be printed with the
		matching entries.

		(Not yet implemented.)

	-verbose
		Display verbose information.

	-Version
		Display the version information for zeek-grep.

	-help
		Display a help message.

	-man
		Display a man page for zeek-grep.

USAGE EXAMPLES

	$ zeek-grep -filter query=mx -filter rcode=0 dns.log
		Show entries for DNS queries that are exactly "mx" or that
		have an rcode value of 0.

	$ zeek-grep -filter id.orig_h=^172.16. dns.log smtp.log http.log
		Show entries with an originator address that starts with
		"172.16.".

	$ zeek-grep -filter answers=/172.16.3. dns.log
		Show entries with an answers field that contains "172.16.3.".

	$ zeek-grep -filter query=$.com	<logfiles>
		Show entries with a query field that ends with ".com".

	$ zeek-grep -filter id.orig_h=^172.16. -filter id.orig_h=^10.0.1 smtp.log http.log
		Show entries with an originator address that starts with
		either "172.16." or "10.0.1".

		Due to a missing final period, the second filter will match 
		on "10.0.1", "10.0.100", "10.0.18", "10.0.1.88", "10.0.1...",
		"10.0.1this.is.a.bad.address", and an infinite number of other
		such strings.

	$ zeek-grep -filter id.orig_h=^192.168.1. -filter id.resp_h=8.8.8.8 -and dns.log
		Show entries with an originator address in the "192.168.1"
		subnet and a responder from "8.8.8.8".

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
NAME = "zeek-grep"
VERS = NAME + " version: 1.0"

#------------------------------------------------------------------------
# Option fields.
#	options handled:
#		-filter			define an output filter
#		-and			"and" the filter results
#		-h			don't print filenames
#		-meta			print metadata from log files
#
#		-verbose		turn on verbose output
#		-help			give usage message and exit
#		-man			give man page and exit
#		-Version		give command version info and exit
#
#


#-----------------------------------------------
# Option values.
#

andflag	   = False			# Flag for AND'ing filter results.
nofilename = False			# Don't show filename.
meta	   = False			# Show-metadata flag.

verbose	= 0				# Verbose flag.
debug	= False				# Debugging flag.

#-----------------------------------------------
# General globbies.
#

filters		= None			# Search terms from command line.

fieldnames	= {}			# Hash of field names.
					# (We only care about the keys.)

checklist	= []			# List of filter tuples to run.

paths = []				# Paths from command line.

#------------------------------------------------------------------------
# Routine:	main()
#
def main():
	"""
	Do everything.
	"""

	#
	# Keep track of what we're doing.
	#
#	current_status()

	#
	# Don't complain if the user ctrl-C's out.
	#
	signal(SIGPIPE, SIG_DFL)

	#
	# Parse the command-line arguments.
	#
	getopts()

	#
	# Parse the filter arguments into filter lists.
	#
	parsefilters()

	#
	# Filter the contents of each log file given on the command line.
	#
	for path in paths:
		checklog(path)

	exit(0)


#------------------------------------------------------------------------
# Routine:	getopts()
#
def getopts():
	"""
	Parse the command line for options.
	"""
	global verbose				# Verbose flag.
	global debug				# Debugging flag.

	global andflag				# "and"-results flag.
	global nofilename			# -h flag.
	global meta				# -meta flag.

	global paths				# Paths from command line.
	global filters				# Search terms.

	#
	# Show the usage message and exit if no options were given.
	#
	if(len(sys.argv) == 1):
		usage(1);

	#
	# Show the manpage if the -man option was given.     
	# (This is done here outside of argparse since argparse wants     
	# a log file to be specified.)
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

	ap.add_argument('-andflag', action='store_true')
	ap.add_argument('-h',	    action='store_true')
	ap.add_argument('-meta',    action='store_true')

	#
	# These options control certain parameters for this script.
	#
	ap.add_argument('-filter', action='append')

	#
	# Now parse the options.
	#
	(args, paths) = ap.parse_known_args()

	#
	# Check for some immediate options.
	#
	if(args.Version):	version()
	if(args.help):		usage(1)

	if(args.verbose):	verbose		= 1
	if(args.debug):		debug		= True

	if(args.andflag):	andflag		= True
	if(args.h):		nofilename	= True
	if(args.meta):		meta		= True

	#
	# Get shorthand holders for some options.
	#
	filters    = args.filter

	#
	# Check that we have something to search and something to search for.
	#
	if(filters == None):
		print "no search terms specified"
		exit(1)

	if(paths == None):
		print "no log files specified"
		exit(2)

	#
	# The verbose flag tells us to display the option values.
	#
	if(verbose):

		print "options:"
		print "\tandflag    - %s" % andflag
		print "\tnofile     - %s" % nofilename
		print "\tmeta       - %s" % meta

		print "filters:"
		for f in filters:
			print "\t<%s>" % f
		print ""

		print "files:"
		for arg in paths:
			print "\t<%s>" % arg
		print ""


#------------------------------------------------------------------------
# Routine:	parsefilters()
#
def parsefilters():
	"""
	Parse the filter-argument values into a list of filter tuples.
	The tuples are (processing function, log field, value).
	"""

	global fieldnames		# Hash of field names to examine.
	global checklist		# List of filter tuples.


	#
	# Decode each command-line filter definition into the internal filter.
	#
	for filt in filters:

		#
		# Split the filter into key/value pieces and ensure we have
		# a "<foo>=<bar>" format.   (minus the parens)
		#
		atoms = filt.split('=')
		if(len(atoms) == 1):
			print "invalid filter format:  \"%s\"" % filt
			exit(10)

		#
		# Save the filter pieces into shorthand variables.
		#
		# The filter value is saved as a lowercase string.
		#
		filtkey = atoms[0]
		filtval = atoms[1].lower()

		#
		# Save the name of the field we're filtering.
		#
		fieldnames[filtkey] = 1

		#
		# Find the filtering function for this filter.
		#
		if(filtval[0] == '^'):
			filtfnc = filter_start
		elif(filtval[0] == '$'):
			filtfnc = filter_end
		elif(filtval[0] == '/'):
			filtfnc = filter_has
		else:
			filtfnc = filter_is

		#
		# If we aren't using the default equality filter, then
		# we need to remove the filter signifier from the start
		# of the filter value.
		#
		if(filtfnc != filter_is):
			filtval = filtval[1:]

		#
		# Build the filter tuple for this filter and add it
		# to the list of filter tuples.
		#
		tup = (filtfnc, filtkey, filtval)
		checklist.append(tup)


#------------------------------------------------------------------------
# Routine:	runfilters()
#
def runfilters(fields):
	"""
	Run the filters over the specified field/value pairs.
	If any of the filters score a hit, then we'll return success.
	If none of the filters match, we'll return failure.
	"""

	match = False				# Matched target flag.
	hits = 0				# Count of hit filters.
	misses = 0				# Count of missed filters.

	#
	# Run the filters on this set of log fields.
	#
	for filt in checklist:
		fn = filt[0]

		#
		# Get the field name and ensure that it's valid for this
		# log file.  If not, we'll skip to the next filter.
		#
		fldind = filt[1]

		if(fields.has_key(fldind) == False):
			continue

		#
		# Get the field from the log entry.
		#
		field = fields[fldind]

		#
		# Call the filter function to determine if this matches.
		#
		if(fn(field, filt[2]) == True):
			hits += 1
			match = True
		else:
			misses += 1

#	print "hits:    %d" % hits
#	print "misses:  %d" % misses

	#
	# If the user wants to logically AND the tests, rather than
	# logically OR them, we'll adjust the return value accordingly.
	#
	if(andflag):
		if (misses == 0):
			match = True
		else:
			match = False

	#
	# Return our result.
	#
	return(match)


#------------------------------------------------------------------------
# Routine:	filter_start()
#
def filter_start(field, target):
	"""
	Check if a log field starts with the specified value.
	A boolean is returned.

	Case-insensitive checks are made.
	"""

	lowfield = field.lower()

	retval = lowfield.startswith(target)

#	print "start:\t<%s>\t<%s>\t" % (field, target), retval
	return(retval)


#------------------------------------------------------------------------
# Routine:	filter_end()
#
def filter_end(field, target):
	"""
	Check if a log field ends with the specified value.
	A boolean is returned.

	Case-insensitive checks are made.
	"""

	lowfield = field.lower()

	retval = lowfield.endswith(target)

#	print "ends:\t<%s>\t<%s>\t" % (field, target), retval
	return(retval)


#------------------------------------------------------------------------
# Routine:	filter_has()
#
def filter_has(field, target):
	"""
	Check if a log field contains the specified value.
	A boolean is returned.

	Case-insensitive checks are made.
	"""

	lowfield = field.lower()

	retval = target in lowfield

#	print "has:\t<%s>\t<%s>\t" % (field, target), retval
	return(retval)


#------------------------------------------------------------------------
# Routine:	filter_is()
#
def filter_is(field, target):
	"""
	Check if a log field is the specified value.
	A boolean is returned.

	Case-insensitive checks are made.
	"""

	lowfield = field.lower()

	retval = lowfield == target

#	print "is:\t<%s>\t<%s>\t" % (field, target), retval
	return(retval)


#------------------------------------------------------------------------
# Routine:	checklog()
#
def checklog(logfile):
	"""
	Read the contents of the given log file and check the log entries
	against the filter list.
	"""

	lines = ()					# Lines from log file.

	#
	# Get the contents of the log file.
	#
	try:
		#
		# Open the log file for reading.
		#
		logfd = open(logfile, 'rU')

		#
		# Read the log.
		#
		lines = logfd.readlines()

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
		print "unable to open zeek log file \"%s\"" % path
		sys.exit(1);

	#
	# Get the names of the fields in this log file.
	#
	for ln in lines:
		if(ln.startswith("#fields")):
			logfields = ln.split("\t")
			logfields.pop(0)
			break

	#
	# Run the filters on each line in this log file.
	# If we find a match, the line will be printed.
	# If -meta was given, we'll print the metadata lines.
	#
	for ln in lines:
		ln = ln.strip()

		#
		# Skip metadata lines, unless we should print them.
		#
		if(ln.startswith("#")):
			if(meta):
				print ln
			continue

		#
		# Build a new dictionary for the line's fields.
		#
		fields = dict()

		#
		# Split the line on the field separator.
		#
		linefields = ln.split("\t")

		#
		# Build the field dictionary from the line and the fields.
		#
		for ind in range(0, len(logfields)):

			lind = logfields[ind]

			fields[lind] = linefields[ind]

		#
		# Run the filters and print the line if it passes the checks.
		#
		if(runfilters(fields) == True):
			print ln


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
	outstr = """zeek-grep [options]

        where [options] are:

		-filter		- define a filter for search log files
		-and		- AND filter results instead of OR'ing them
		-meta		- display metadata lines from log files
		-h		- don't display log filenames (NYI)

                -verbose        - give verbose output
                -Version        - show version and exit
                -help           - show usage message
                -man            - show man page
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
# Routine:	main()
#
def current_status():

	print '''

	- implement the -h option

	- implement the -cs option

	- only display metadata for files that have matching entries

	- implement the -nilter option

	- implement the "any" special field name in filters

- docs


----------------------------------------------------------------

	'''


#------------------------------------------------------------------------

#
# Do everything.
#
if(__name__ == '__main__'):
	main()
	sys.exit(0)

#------------------------------------------------------------------------

