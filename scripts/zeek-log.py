#!/usr/bin/env python
#

#
# Revision History
#	1.0	Initial revision.					191104
#		This version is a copy of bro-log.py v1.10.
#		This is to mark the move from bro to zeek.
#		The only real changes were in the command names.
#	1.1	Added support for ntp-base and ntp-ctl.log files.	191119
#	1.2	Added support for ntp-mode7.log files.			191119
#	1.3	Added support for ntp-std.log files.			191125
#	1.4	Added support for ntp-kisscode.log files.		191125
#	1.5	Multiple different logfiles may be given.		191126
#	1.6	Fixed bug so unsupported logfiles won't kill zeek-log.	200116
#	1.7	Unsupported logfiles show all fields, not just tstmp.	200116
#
#	Written by Wayne Morrison, 191104.
#

man = """
summarizes data from a set of zeek log files

zeek-log summarizes data from a zeek log, and provides shortcuts for
displaying log-specific fields.  This command may be used with any zeek log
file.  zeek-log's primary functionality is to provide output formatting
formatting and log-specific selection.

Multiple log files of different protocols may be given on a single command
line.  The files will be displayed in order, as one would expect.  Also,
different selection options for each log type may be specified

zeek-log has predefined lists of fields that are displayed when log files of
certain protocols are given on the command line.  The supported protocols are
DNS, NTP, and SMTP.  Protocols unsupported by zeek-log may be usefully
displayed when used with the -fields option.

Unsupported log files may be used with zeek-log, and they will display all
the fields in the log file.  This is essentially equivalent to just looking
at the log file directly, except that zeek-log display the log in a nice,
orderly fashion with columns lining up cleanly.

An example of log-specific selection is that the "-sender" option used in
conjunction with an SMTP zeek log will have zeek-log display sender-specific
data from the log file.  The type of the zeek log is determined by the value
of the log file's "#path" line.

The zeek-cut command parses the specified zeek log and provides the selected
data to zeek-log.  The data are formatted for a more readable display than is
provided by zeek-cut.

A set of selection options select the data fields to display.  The selection
options are described in a section below.

If no selection option is given, then a summary is given that consists of
certain fields specific to the log file's type.  For example, when an SMTP
zeek log is specified without a selection option being given, the data from
the following SMTP header fields, in this order:

	MailFrom
	RcptTo
	From
	To
	Cc
	Reply-To
	Date
	Subject

If no default field list has been set up for particular type of zeek-log, then
all the fields will be displayed.

Output may be given in either normal or CSV format.  When given in normal
format, zeek-log tries to put the data into columns that will read nicely.
CSV format forces the output into columns for display in a spreadsheet
program, or another program which understands CSV.


SELECTION OPTIONS

There are several options that allow data selection from zeek logfiles.  Some
options provide shorthand ways to refer to protocol-specific sets of options.
There are others that allow users to choose the data to be displayed.

There are default fields defined for each supported protocol.  If a logfile
for an unsupported protocol is given to zeek-log, then a default set of
options will be displayed.  This set is the timestamp of each entry, since
that field appears to be standard to all types of logfile.

The -fields option allows a user to select the specific set of fields to be
displayed in an invocation of zeek-log.  Multiple fields must be separated by
commas.  If the default set of options should be included along with the
user-selected fields, then the -usedefs option adds the defaults to the user's
field list.

zeek-log's selection options select the fields from each entry that will be
displayed.  Thinking of the zeek-log output as a table, these options select
the columns that will be shown.  There are selection options that are specific
to a type of zeek logfile.  These are described here, in logfile-specific
sections.

    Selection Options for DNS zeek Logs

	The fields displayed for a dns.log file will depend on the argument
	given to the -dns option.

	The following option arguments will display these fields:

		-dns default	(defaults)

			ORIGHOST
			RESPHOST
			QUERY
			QTYPE_NAME
			ANSWERS

			These values will also be displayed if a dns.log
			file is named on the command line, but the -dns
			option is not specified.

		-dns defts	(DNS default + time)
			TS
			ORIGHOST
			RESPHOST
			QUERY
			QTYPE_NAME
			ANSWERS

		-dns query	(DNS query fields)
			ORIGHOST
			QUERY
			QCLASS_NAME
			QTYPE_NAME
			RCODE_NAME
			ANSWERS

		-dns flags	(DNS flag fields)
			TS
			UID
			ORIGHOST
			RESPHOST
			TRANS_ID
			QUERY
			QCLASS_NAME
			QTYPE_NAME
			RCODE_NAME
			AA
			TC
			RD
			RA
			Z
			ANSWERS
			REJECTED

		-dns times	(DNS flag fields)
			TS
			UID
			ORIGHOST
			RESPHOST
			RTT
			TTLS

		-dns all	(all DNS fields)

			If the "all" argument is given with -dns, then all
			the fields in each line will be displayed.  This
			has the same effect as just using zeek-cut, but it
			does put the output into a columnar format.

    Selection Options for SMTP zeek Logs

	The fields displayed for an smtp.log file will depend on the argument
	given to the -smtp option.

	The following option arguments will display these fields:

		-smtp default	(defaults)
			MAILFROM
			RCPTTO
			FROM
			TO
			CC
			REPLY_TO
			DATE
			SUBJECT

			These values will also be displayed if an smtp.log
			file is named on the command line, but the -smtp
			option is not specified.

		-smtp defts	(SMTP default + time)
			TS
			MAILFROM
			RCPTTO
			FROM
			TO
			CC
			REPLY_TO
			DATE
			SUBJECT

		-smtp sender	(SMTP sender fields)
			ORIGHOST
			RESPHOST
			HELO
			FROM
			MAILFROM
			REPLY_TO

		-smtp recipient	(SMTP recipient fields)
			ORIGHOST
			RESPHOST
			RCPTTO
			TO
			CC
			IN_REPLY_TO

		-smtp recip
			This is an alias for "-smtp recipient".

		-smtp names	(SMTP sender/receiver fields)
			ORIGHOST
			RESPHOST
			HELO
			FROM
			MAILFROM
			REPLY_TO
			RCPTTO
			TO
			CC
			IN_REPLY_TO

		-smtp justnames	(SMTP sender/receiver fields)
			HELO
			FROM
			MAILFROM
			REPLY_TO
			RCPTTO
			TO
			CC
			IN_REPLY_TO

		-smtp all	(all SMTP fields)

			If the "all" argument is given with -smtp, then all
			the fields in each line will be displayed.  This
			has the same effect as just using zeek-cut, but it
			does put the output into a columnar format.


    Selection Options for NTP zeek Logs

    Four different log files provide NTP protocol information.  These
    files have their own options and default displays.  The files are:

		ntp.log			complete log of NTP use
		ntp-extensions.log	log of NTP extension data
		ntp-oldversions.log	log of NTP packets using old
					versions of NTP
		ntp-servers.log		summarization of NTP servers

    The options and field selectors for each log are given below.

	ntp.log
	-------

	The fields displayed for an ntp.log file will depend on the argument
	given to the -ntp option.

	The following option arguments will display these fields:

		-ntp default	(defaults)

			ORIGHOST
			RESPHOST
			STRATUMNAME
			MODENAME

			These values will also be displayed if an ntp.log
			file is named on the command line, but the -ntp
			option is not specified.

		-ntp defts	(defaults, with the timestamp)

			TS
			ORIGHOST
			RESPHOST
			STRATUMNAME
			MODENAME

		-ntp times	(NTP time fields and host data)

			ORIGHOST
			RESPHOST
			MODENAME
			PRECISION
			REF_T
			ORIGINATE_T
			RECEIVE_T
			XMIT_T

		-ntp stats	(NTP statistics fields and host data)

			ORIGHOST
			RESPHOST
			STRATUMNAME
			MODENAME
			POLL
			PRECISION
			DELAY

		-ntp all	(all NTP fields)

			If the "all" argument is given with -ntp, then all
			the fields in each line will be displayed.  This
			has the same effect as just using zeek-cut, but it
			does put the output into a columnar format.

	A colon and a comma-separated list of field names can be appended
	to the option argument in order to include additional fields with
	the predefined set of fields.  For example,

		-ntp defts:uid,poll

	will include the connection UID and the poll value with the default
	fields and the timestamp.

	ntp-base.log
	------------

	The ntp-base.log file contains records for all the NTP messages that
	have been received.  This includes the standard (modes 1-5) messages,
	the control messages (mode 6), and the mode 7 messages.  The data in
	ntp-base.log is primarily from the standard messages.  Basic data for
	the control and mode 7 messages are included to make it easier to see
	how those messages fit into the overall NTP stream.

	The fields displayed for an ntp-base.log file will depend on the
	argument given to the -ntpbase option.

	The following option arguments will display these fields:

		-ntpbase default	(defaults)

			ORIGHOST
			RESPHOST
			STRATUMNAME
			MODENAME

			These values will also be displayed if an ntp-base.log
			file is named on the command line, but the -ntpbase
			option is not specified.

		-ntpbase defts		(defaults, with the timestamp)

			TS
			ORIGHOST
			RESPHOST
			STRATUMNAME
			MODENAME

		-ntpbase times		(NTP time fields and host data)

			ORIGHOST
			RESPHOST
			MODENAME
			PRECISION
			REF_T
			ORIGINATE_T
			RECEIVE_T
			XMIT_T

		-ntpbase stats		(NTP statistics fields and host data)

			ORIGHOST
			RESPHOST
			STRATUMNAME
			MODENAME
			POLL
			PRECISION
			DELAY

		-ntpbase stratum	(NTP stratum fields)

			ORIGHOST
			RESPHOST
			MODE
			STRATUM
			STRATUMNAME
			KISS-CODE
			REF-ID
			REF-ADDR

		-ntpbase all		(all NTP fields)

			If the "all" argument is given with -ntpbase, then all
			the fields in each line will be displayed.  This
			has the same effect as just using zeek-cut, but it
			does put the output into a columnar format.

	A colon and a comma-separated list of field names can be appended
	to the option argument in order to include additional fields with
	the predefined set of fields.  For example,

		-ntpbase defts:uid,poll

	will include the connection UID and the poll value with the default
	fields and the timestamp.

	ntp-ctl.log
	-----------

	The fields displayed for an ntp-ctl.log file will depend on the argument
	given to the -ntpctl option.

	The following option arguments will display these fields:

		-ntpctl default	(defaults)

			ORIGHOST
			RESPHOST
			OPCODENAME
			RESPBIT
			ERRBIT
			MOREBIT
			SEQUENCE
			ASSOC-ID
			STATUS

			These values will also be displayed if an ntp-ctl.log
			file is named on the command line, but the -ntpctl
			option is not specified.

		-ntpctl defts		(defaults, with the timestamp)

			TS
			ORIGHOST
			RESPHOST
			OPCODENAME
			RESPBIT
			ERRBIT
			MOREBIT
			SEQUENCE
			ASSOC-ID
			STATUS

		-ntpctl crypto		(NTP cryptographic fields)

			ORIGHOST
			RESPHOST
			OPCODENAME
			ASSOC-ID
			KEY-ID
			CRYPTO-CKSUM

		-ntpctl data		(NTP data fields)

			ORIGHOST
			RESPHOST
			OPCODENAME
			ASSOC-ID
			DATA

		-ntpctl all	(all NTP control-message fields)

			If the "all" argument is given with -ntpctl, then all
			the fields in each line will be displayed.  This
			has the same effect as just using zeek-cut, but it
			does put the output into a columnar format.

	A colon and a comma-separated list of field names can be appended
	to the option argument in order to include additional fields with
	the predefined set of fields.  For example,

		-ntpctl crypto:data

	will include the data field with the cryptographic fields.

	ntp-extensions.log
	------------------

	The fields displayed for an ntp.log file will depend on the argument
	given to the -ntpext option.

	NOTE:  zeek lost some features in the migration from bro.  The
	       extension data is not currently returned by zeek, so the
	       ntp-extensions.log is not created by ntp.zeek.  Thus, the
	       data and options described below are not currently available.

	The following option arguments will display these fields:

		-ntpext default		(defaults)

			ORIGHOST
			RESPHOST
			STRATUMNAME
			ENTRYTYPE

			These values will also be displayed if an
			ntp-extensions.log file is named on the command
			line, but the -ntpext option is not specified.

		-ntpext defts		(defaults, with the timestamp)

			TS
			ORIGHOST
			RESPHOST
			STRATUMNAME
			ENTRYTYPE

		-ntpext data		(hosts and extension data)

			ORIGHOST
			RESPHOST
			STRATUMNAME
			EXCESSLEN
			FIELDTYPE
			EXTLEN
			ENTRYTYPE

		-ntpext all		(all NTP extensions fields)

			If the "all" argument is given with -ntpext,
			then all the fields in each line will be
			displayed.  This has the same effect as just
			using zeek-cut, but it does put the output
			into a columnar format.

	A colon and a comma-separated list of field names can be appended
	to the option argument in order to include additional fields with
	the predefined set of fields.  For example,

		-ntpext data:uid

	will include the connection UID with the data fields.

	ntp-kisscode.log
	------------------

	The fields displayed for an ntp-kisscode.log file will depend on the
	argument given to the -ntpkiss option.

	The following option arguments will display these fields:

		-ntpkiss default		(defaults)

			ORIGHOST
			RESPHOST
			MODENAME
			STRATUMNAME
			KISSCODE
			REFID

			These values will also be displayed if an
			ntp-kisscode.log file is named on the command
			line, but the -ntpkiss option is not specified.

		-ntpkiss defts		(defaults, with the timestamp)

			TS
			ORIGHOST
			RESPHOST
			MODENAME
			STRATUMNAME
			KISSCODE
			REFID

		-ntpkiss data		(untranslated data)

			ORIGHOST
			RESPHOST
			MODE
			STRATUM
			KISSCODE
			REFID

		-ntpkiss all		(all NTP kiss-code/ref-id fields)

			If the "all" argument is given with -ntpkiss,
			then all the fields in each line will be
			displayed.  This has the same effect as just
			using zeek-cut, but it does put the output
			into a columnar format.

	A colon and a comma-separated list of field names can be appended
	to the option argument in order to include additional fields with
	the predefined set of fields.  For example,

		-ntpkiss default:mode,stratum

	will include the mode number and stratum number with the data fields.


	ntp-mode7.log
	-----------

	The fields displayed for an ntp-mode7.log file will depend on the
	argument given to the -ntpm7 option.

	The following option arguments will display these fields:

		-ntpm7 default	(defaults)

			ORIGHOST
			RESPHOST
			REQCODE
			SEQUENCE
			IMPLEMENTATION
			ERROR

			These values will also be displayed if an ntp-mode7.log
			file is named on the command line, but the -ntpm7
			option is not specified.

		-ntpm7 defts		(defaults, with the timestamp)

			TS
			ORIGHOST
			RESPHOST
			REQCODE
			SEQUENCE
			IMPLEMENTATION
			ERROR

		-ntpm7 data		(NTP data fields)

			ORIGHOST
			RESPHOST
			REQCODE
			SEQUENCE
			DATA

		-ntpm7 all	(all NTP control-message fields)

			If the "all" argument is given with -ntpm7, then all
			the fields in each line will be displayed.  This
			has the same effect as just using zeek-cut, but it
			does put the output into a columnar format.

	A colon and a comma-separated list of field names can be appended
	to the option argument in order to include additional fields with
	the predefined set of fields.  For example,

		-ntpm7 data:ts

	will include the timestamp field with the data fields.

	ntp-oldversions.log
	-------------------

	The fields displayed for an ntp-oldversions.log file will depend
	on the argument given to the -ntpold option.

	The following option arguments will display these fields:

		-ntpold default		(defaults)

			ORIGHOST
			RESPHOST
			VERSION
			MODENAME
			STRATUMNAME

			These values will also be displayed if an
			ntp-oldversions.log file is named on the command
			line, but the -ntpold option is not specified.

		-ntpold defts		(defaults, with the timestamp)

			TS
			ORIGHOST
			RESPHOST
			VERSION
			MODENAME
			STRATUMNAME

		-ntpold all		(all NTP old-versions fields)

			If the "all" argument is given with -ntpold,
			then all the fields in each line will be
			displayed.  This has the same effect as just
			using zeek-cut, but it does put the output
			into a columnar format.

	A colon and a comma-separated list of field names can be appended
	to the option argument in order to include additional fields with
	the predefined set of fields.  For example,

		-ntpold default:uid

	will include the connection UID with the default fields.

	ntp-servers.log
	---------------

	The fields displayed for an ntp-servers.log file will depend
	on the argument given to the -ntpservers option.

	The following option arguments will display these fields:

		-ntpservers default	(defaults)

			TS
			HADDR
			STRATUMNAME
			RESPONSES
			ENTRYTYPE

			These values will also be displayed if an
			ntp-servers.log file is named on the command
			line, but the -ntpservers option is not specified.

		-ntpservers defts	(defaults, with the timestamp)

			TS
			HADDR
			STRATUMNAME
			RESPONSES
			ENTRYTYPE

		-ntpservers all		(all NTP servers fields)

			If the "all" argument is given with -ntpservers,
			then all the fields in each line will be
			displayed.  This has the same effect as just
			using zeek-cut, but it does put the output
			into a columnar format.

	A colon and a comma-separated list of field names can be appended
	to the option argument in order to include additional fields with
	the predefined set of fields.  For example,

		-ntpservers default:stratum

	will include the stratum number with the default fields.

	ntp-std.log
	------------

	The ntp-std.log file contains records for all the NTP standard
	(modes 1-5) messages that have been received.  The log format and
	options for this log file are the same as those of the ntp-base.log
	file, except that -ntpstd option selects the fields to be displayed.
	See the section on ntp-base.log above for details on arguments to
	the -ntpstd option.

	The fields displayed for an ntp-std.log file will depend on the
	argument given to the -ntpstd option.


FILTER OPTIONS

zeek-log's filter option selects the entries from the logfile that will
be displayed.  Thinking of the zeek-log output as a table, these filter
options select the rows that will be shown.

Filters are defined according to the field names of the zeek logfiles.
For example, a filter may be defined that looks for a value in an SMTP
logfile in the "mailfrom" or "from" fields.  A filter will contain a
field name and a data value.  The specified field will be searched for
the data value, and only those entries with a match in that field will
be displayed.

Currently, zeek-log's filters are fairly simple.  The filter's data
value only has to appear inside the field values, there is not (yet?)
any regular-expression style of searching, no way of anchoring the
data value at the beginning of the field data, wildcards are not
supported.

Filters may only be defined for fields that are appearing in the data
returned by zeek-cut.  If the only field names being displayed from an
SMTP logfile are the "from" and "to" fields, then defining a filter
for the "subject" field will have no effect.

Multiple filters may be defined for a single invocation of zeek-log.
These filters are logically ORed, not ANDed.

Examples:

   1. zeek-log -filter from=example.com smtp.log

	This filter will only display entries with "example.com"
	in the "from" field of an SMTP logfile.
	The following values would match this filter:
		bob@example.com
		bob@testexample.com
		bob@test.example.com
		bob@example.com.au
		bob@example.commerce.gov

   2. zeek-log -filter qtype_name=NS dns.log

	This filter will only display entries with "NS" in
	the "qtype_name" field of a DNS logfile.
	The following values would match this filter, and
	are expected possibilities for this field:
		NS
		NSAP
		NSAP_PTR

   3. zeek-log -filter from=bob@example.com -filter from=mary@example.net dns.log

	This filter will only display entries that contain
	*either* "bob@example.com" or "mary@example.com"
	The following values would match this filter:
		bob@example.com
		mary@example.net
		marybob@example.com
		mary@example.com.

   4. zeek-log -filter proto=tcp -filter rcode_name=NXDOMAIN dns.log

	This filter will only display entries with "tcp" in
	the "proto" field or "NXDOMAIN" in the "rcode_name"
	field of a DNS logfile.

Currently, protocol translations are not done for field values.  If you
want to display entries with a query type of TXT, then either of these
filters must be used:

	-filter qtype=16
	-filter qtype_name=TXT

Defining a filter for "qtype=TXT" will not work as hoped.


SYNOPSIS

    zeek-log [options] <logname1> ... <lognameN>

OPTIONS

    zeek-log takes the following options:

	-csv
		Display information in CSV format.

	-date
		Translate date fields to human-readable format.
		This is implemented by passing the -d option to
		zeek-cut.  zeek-cut itself determines which fields
		should be translated and to translate them.

	-dns <subcommand>
		Display DNS entries from a dns.log.
		The <subcommand> defines which fields will be displayed.
		(DNS)

	-fields
		Specify a set of field names that will be displayed.
		This is a comma-separated list of names for the data
		stored in a zeek logfile.

	-filter
		Define a filter select entries to display.
		This may be used multiple times in a single execution.

	-logfiles
		Show the supported zeek log files.

	-ntp <subcommand>
		Display NTP data from an ntp.log.
		The <subcommand> defines which fields will be displayed.
		(NTP)

	-ntpbase <subcommand>
		Display NTP data from an ntp-base.log.
		The <subcommand> defines which fields will be displayed.
		(NTP)

	-ntpctl <subcommand>
		Display NTP control data from an ntp-ctl.log.
		The <subcommand> defines which fields will be displayed.
		(NTP)

	-ntpext <subcommand>
		Display NTP extensions data from an ntp-extensions.log.
		The <subcommand> defines which fields will be displayed.

		zeek lost some features in the migration from bro.  The
		extension data is not currently returned by zeek, so the
		ntp-extensions.log is not created by ntp.zeek.  Thus, the
		data and options described below are not currently available.

		(NTP)

	-ntpkiss <subcommand>
		Display NTP kiss-code and ref-id data from an ntp-kisscode.log.
		The <subcommand> defines which fields will be displayed.
		(NTP)

	-ntpm7 <subcommand>
		Display NTP mode-7 data from an ntp-mode7.log.
		The <subcommand> defines which fields will be displayed.
		(NTP)

	-ntpold <subcommand>
		Display data on use of old versions of NTP from an
		ntp-oldversions.log.
		The <subcommand> defines which fields will be displayed.
		(NTP)

	-ntpservers <subcommand>
		Display data on NTP servers from an ntp-servers.log.
		The <subcommand> defines which fields will be displayed.
		(NTP)

	-ntpstd <subcommand>
		Display NTP data from an ntp-std.log.
		The <subcommand> defines which fields will be displayed.
		(NTP)

	-smtp <subcommand>
		Display SMTP entries from an smtp.log.
		The <subcommand> defines which fields will be displayed.
		(SMTP)

	-showfields
		Display the field names and field types of a zeek logfile.

	-subcmds <protocol>
		Display the option subcommands for the specified protocol.
		Strictly speaking, <protocol> isn't really a protocol;
		rather, it's the type of a zeek log file, such as dns,
		ntp, or ntpservers.

		If "all" is given for the protocol, or if no protocol is
		given at all, then all the supported protocols and their
		subcommands will be displayed.

	-usedefs
		Include the default fields in the output.  This option only
		takes effect when used in conjunction with the -fields option.

	-verbose
		Display verbose information.

	-Version
		Display the version information for zeek-log.

	-help
		Display a help message.

	-man
		Display this manpage.


SUPPORTING NEW LOGS

zeek-log is a general tool for handling multiple types of zeek logfiles.
Adding support for new logfiles is not difficult and some support can
be added very quickly.

There are several particular places that must be modified in order to
support additional zeek logfiles:

	- The getopts() routine must be modified to support a new
	  selection option.

	- The getfields() routine must be modified to specify the fields
	  to be displayed for the various selection option arguments.

	- Add field "constants" for the log file's fields.

It would be easiest to search for all "ntpbase" in the script and add 
code that provides similar functionality as required for the new log file.

SEE ALSO

        zeek-cut(1)

AUTHOR

        Wayne Morrison, Wayne.Morrison@parsons.com

"""

todostr = '''

in progress:

to do:
	- move subcommand organizations out of getfields() and
	  into global arrays

	- allow multiple different protocol logs on command line

	- complex options (e.g., -subnet)

	- data consolidation  (e.g., counting labels in a domain name)

'''


import os
import sys
import argparse
import subprocess

from signal import signal, SIGPIPE, SIG_DFL

#
# Version information.
#
NAME = "zeek-log"
VERS = NAME + " version: 1.7"

#------------------------------------------------------------------------
# Option fields.
#	options handled:
#		-verbose	Turn on verbose output.
#		-help		Give usage message and exit.
#		-man		Give manpage and exit.
#		-Version	Give command version info and exit.
#
#		-csv		Give output in CSV format.
#		-date	 	Translate date fields to human-readable format.
#		-fields		Specify fields to display.
#		-filter		Define a selection filter.
#		-showfields	Show the fields of a zeek logfile.
#		-logfiles	Show the supported zeek log files.
#		-subcmds	Show the subcommands for each protocol option.
#		-usedefs	Use the default fields with user fields.
#
#		-dns		Display DNS data from dns.log.
#		-ntp		Display NTP data from ntp.log.
#		-ntpbase	Display NTP data from ntp-base.log.
#		-ntpctl		Display NTP data from ntp-ctl.log.
#		-ntpext		Display NTP data from ntp-extensions.log.  (NYI)
#		-ntpkiss	Display NTP data from ntp-kisscode.log.
#		-ntpm7		Display NTP data from ntp-mode7.log.
#		-ntpold		Display NTP data from ntp-oldversions.log.
#		-ntpstd		Display NTP data from ntp-std.log.
#		-ntpservers	Display NTP data from ntp-servers.log.
#		-smtp		Display SMTP data from smtp.log.
#


#-----------------------------------------------
# Option values.
#

loglist	= []				# Names of zeek logfiles.

verbose = 0				# Verbose flag.
csv = False				# Output in CSV format.

showfields = 0				# Show logfile's fields flag.

usedefs = False				# Use default fields.
userfields = None			# User-selected fields.

dnsfields = None			# DNS-related fields flag.
smtpfields = None			# SMTP-related fields flag.

ntpfields = None			# NTP-related fields flag.
ntpbasefields = None			# NTP-base-related fields flag.
ntpctlfields = None			# NTP-ctl-related fields flag.
ntpm7fields = None			# NTP-mode7-related fields flag.
ntpextfields = None			# NTP-extensions-related fields flag.
ntpkissfields = None			# NTP-kisscode-related fields flag.
ntpoldfields = None			# NTP-old-versions-related fields flag.
ntpsrvrfields = None			# NTP-servers-related fields flag.
ntpstdfields = None			# NTP-std-related fields flag.

filters = None				# Filters to apply.

dateflag = False			# Include zeek-cut's -d flag.


#-----------------------------------------------
# Default values.
#

ZEEKCUT = "zeek-cut"			# zeek log parser.

MAXSTRLEN = 50				# Maximum length of string to display.


#------------------------------------------------------------------------
#
# Standard indices for various zeek logfiles.
# Additional indices may be added by various plugins.
#

logtypes = [				# Supported zeek log file.
		'dns.log',
		'ntp.log',
		'ntp-base.log',
		'ntp-ctl.log',
		'ntp-kisscode.log',
		'ntp-mode7.log',
		'ntp-oldversions.log',
		'ntp-servers.log',
		'ntp-std.log',
		'smtp.log'
	   ]

subcmds = {}				# Hash of each logfile's subcommands.

#
# Indices to DNS field data.
#
DNS_TS		= 'ts'
DNS_UID		= 'uid'
DNS_ORIGHOST	= 'id.orig_h'
DNS_ORIGPORT	= 'id.orig_p'
DNS_RESPHOST	= 'id.resp_h'
DNS_RESPPORT	= 'id.resp_p'
DNS_PROTO	= 'proto'
DNS_TRANS_ID	= 'trans_id'
DNS_RTT		= 'rtt'
DNS_QUERY	= 'query'
DNS_QCLASS	= 'qclass'
DNS_QCLASS_NAME	= 'qclass_name'
DNS_QTYPE	= 'qtype'
DNS_QTYPE_NAME	= 'qtype_name'
DNS_RCODE	= 'rcode'
DNS_RCODE_NAME	= 'rcode_name'
DNS_AA		= 'AA'
DNS_TC		= 'TC'
DNS_RD		= 'RD'
DNS_RA		= 'RA'
DNS_Z		= 'Z'
DNS_ANSWERS	= 'answers'
DNS_TTLS	= 'TTLs'
DNS_REJECTED	= 'rejected'

subcmds['dns'] = ['default', 'defts', 'all', 'query', 'flags', 'times']

#
# Indices to SMTP field data.
#
SMTP_TS			= 'ts'
SMTP_UID		= 'uid'
SMTP_ORIGHOST		= 'id.orig_h'
SMTP_ORIGPORT		= 'id.orig_p'
SMTP_RESPHOST		= 'id.resp_h'
SMTP_RESPPORT		= 'id.resp_p'
SMTP_TRANS_DEPTH	= 'trans_depth'
SMTP_HELO		= 'helo'
SMTP_MAILFROM		= 'mailfrom'
SMTP_RCPTTO		= 'rcptto'
SMTP_DATE		= 'date'
SMTP_FROM		= 'from'
SMTP_TO			= 'to'
SMTP_CC			= 'cc'
SMTP_REPLY_TO		= 'reply_to'
SMTP_MSG_ID		= 'msg_id'
SMTP_IN_REPLY_TO	= 'in_reply_to'
SMTP_SUBJECT		= 'subject'
SMTP_X_ORIGINATING_IP	= 'x_originating_ip'
SMTP_FIRST_RECEIVED	= 'first_received'
SMTP_SECOND_RECEIVED	= 'second_received'
SMTP_LAST_REPLY		= 'last_reply'
SMTP_PATH		= 'path'
SMTP_USER_AGENT		= 'user_agent'
SMTP_TLS		= 'tls'
SMTP_FUIDS		= 'fuids'

subcmds['smtp'] = ['default', 'defts', 'all', 'sender', 'recipient', 'recip', 'names', 'justnames']

#
# Indices to NTP field data.
#
NTP_TS			= 'ts'
NTP_UID			= 'uid'
NTP_ORIGHOST		= 'id.orig_h'
NTP_ORIGPORT		= 'id.orig_p'
NTP_RESPHOST		= 'id.resp_h'
NTP_RESPPORT		= 'id.resp_p'
NTP_VERSION		= 'version'
NTP_MODE		= 'mode'
NTP_STRATUM		= 'stratum'
NTP_POLL		= 'poll'
NTP_PRECISION		= 'precision'
NTP_DELAY		= 'root_delay'
NTP_DISPERSION		= 'root_disp'
NTP_REFID		= 'ref_id'
NTP_REF_T		= 'ref_time'
NTP_ORIGINATE_T		= 'org_time'
NTP_RECEIVE_T		= 'rec_time'
NTP_XMIT_T		= 'xmt_time'
NTP_NUMEXTS		= 'num_exts'

subcmds['ntp'] = ['default', 'defts', 'all', 'times', 'stats']

#
# Indices to NTP field data from the base and standard files.
#
NTP_BASE_TS		= 'ts'
NTP_BASE_UID		= 'uid'
NTP_BASE_ORIGHOST	= 'id.orig_h'
NTP_BASE_ORIGPORT	= 'id.orig_p'
NTP_BASE_RESPHOST	= 'id.resp_h'
NTP_BASE_RESPPORT	= 'id.resp_p'
NTP_BASE_VERSION	= 'version'
NTP_BASE_MODE		= 'mode'
NTP_BASE_MODENAME	= 'modename'
NTP_BASE_STRATUM	= 'stratum'
NTP_BASE_STRATUMNAME	= 'stratumname'
NTP_BASE_POLL		= 'poll'
NTP_BASE_PRECISION	= 'precision'
NTP_BASE_DELAY		= 'root_delay'
NTP_BASE_DISPERSION	= 'root_disp'
NTP_BASE_KISSCODE	= 'kiss_code'
NTP_BASE_REFID		= 'ref_id'
NTP_BASE_REFADDR	= 'ref_addr'
NTP_BASE_REF_T		= 'ref_time'
NTP_BASE_ORIGINATE_T	= 'org_time'
NTP_BASE_RECEIVE_T	= 'rec_time'
NTP_BASE_XMIT_T		= 'xmt_time'
NTP_BASE_NUMEXTS	= 'num_exts'
NTP_BASE_KEYID		= 'key_id'
NTP_BASE_DIGEST		= 'digest'

subcmds['ntpbase'] = ['default', 'defts', 'all', 'times', 'stats', 'stratum']
subcmds['ntpstd']  = ['default', 'defts', 'all', 'times', 'stats', 'stratum']

#
# Indices to NTP-ctl field data.
#
NTP_CTL_TS		= 'ts'
NTP_CTL_UID		= 'uid'
NTP_CTL_ORIGHOST	= 'id.orig_h'
NTP_CTL_ORIGPORT	= 'id.orig_p'
NTP_CTL_RESPHOST	= 'id.resp_h'
NTP_CTL_RESPPORT	= 'id.resp_p'
NTP_CTL_VERSION		= 'version'
NTP_CTL_MODE		= 'mode'
NTP_CTL_MODENAME	= 'modename'
NTP_CTL_OPCODE		= 'opcode'
NTP_CTL_OPCODENAME	= 'opcodename'
NTP_CTL_RESPBIT		= 'respbit'
NTP_CTL_ERRBIT		= 'errbit'
NTP_CTL_MOREBIT		= 'morebit'
NTP_CTL_SEQUENCE	= 'sequence'
NTP_CTL_STATUS		= 'status'
NTP_CTL_ASSOCID		= 'associd'
NTP_CTL_DATA		= 'data'
NTP_CTL_KEYID		= 'keyid'
NTP_CTL_CRYPTO_CKSUM	= 'crypto_cksum'

subcmds['ntpctl'] = ['default', 'defts', 'all', 'crypto', 'data']

#
# Indices to NTP mode-7 field data.
#
NTP_MODE7_TS		 = 'ts'
NTP_MODE7_UID		 = 'uid'
NTP_MODE7_ORIGHOST	 = 'id.orig_h'
NTP_MODE7_ORIGPORT	 = 'id.orig_p'
NTP_MODE7_RESPHOST	 = 'id.resp_h'
NTP_MODE7_RESPPORT	 = 'id.resp_p'
NTP_MODE7_VERSION	 = 'version'
NTP_MODE7_MODE		 = 'mode'
NTP_MODE7_MODENAME	 = 'modename'
NTP_MODE7_REQCODE	 = 'reqcode'
NTP_MODE7_AUTHBIT	 = 'authbit'
NTP_MODE7_SEQUENCE	 = 'sequence'
NTP_MODE7_IMPLEMENTATION = 'impl'
NTP_MODE7_ERROR		 = 'err'
NTP_MODE7_DATA		 = 'data'

subcmds['ntpm7'] = ['default', 'defts', 'all', 'data']

#
# Indices to NTP extensions field data.
#
NTP_EXT_TS		= 'ts'
NTP_EXT_UID		= 'uid'
NTP_EXT_ORIGHOST	= 'id.orig_h'
NTP_EXT_ORIGPORT	= 'id.orig_p'
NTP_EXT_RESPHOST	= 'id.resp_h'
NTP_EXT_RESPPORT	= 'id.resp_p'
NTP_EXT_PROTO		= 'proto'
NTP_EXT_STRATUM		= 'stratum'
NTP_EXT_STRATUMNAME	= 'stratumname'
NTP_EXT_EXCESSLEN	= 'excesslen'
NTP_EXT_FIELDTYPE	= 'fieldtype'
NTP_EXT_EXTLEN		= 'extlen'
NTP_EXT_ENTRYTYPE	= 'entrytype'

subcmds['ntpext'] = ['default', 'defts', 'all', 'data']

#
# Indices to NTP kiss-code/ref-id field data.
#
NTP_KISS_TS		= 'ts'
NTP_KISS_UID		= 'uid'
NTP_KISS_ORIGHOST	= 'id.orig_h'
NTP_KISS_ORIGPORT	= 'id.orig_p'
NTP_KISS_RESPHOST	= 'id.resp_h'
NTP_KISS_RESPPORT	= 'id.resp_p'
NTP_KISS_MODE		= 'mode'
NTP_KISS_MODENAME	= 'modename'
NTP_KISS_STRATUM	= 'stratum'
NTP_KISS_STRATUMNAME	= 'stratumname'
NTP_KISS_KISSCODE	= 'kiss_code'
NTP_KISS_REFID		= 'ref_id'

subcmds['ntpkiss'] = ['default', 'defts', 'all']

#
# Indices to NTP old-versions field data.
#
NTP_OLDVERS_TS			= 'ts'
NTP_OLDVERS_UID			= 'uid'
NTP_OLDVERS_ORIGHOST		= 'id.orig_h'
NTP_OLDVERS_ORIGPORT		= 'id.orig_p'
NTP_OLDVERS_RESPHOST		= 'id.resp_h'
NTP_OLDVERS_RESPPORT		= 'id.resp_p'
NTP_OLDVERS_VERSION		= 'version'
NTP_OLDVERS_MODE		= 'mode'
NTP_OLDVERS_MODENAME		= 'modename'
NTP_OLDVERS_STRATUM		= 'stratum'
NTP_OLDVERS_STRATUMNAME		= 'stratumname'

subcmds['ntpold'] = ['default', 'defts', 'all']

#
# Indices to NTP servers field data.
#
NTP_SERVERS_TS			= 'ts'
NTP_SERVERS_HADDR		= 'haddr'
NTP_SERVERS_STRATUM		= 'stratum'
NTP_SERVERS_STRATUMNAME		= 'stratumname'
NTP_SERVERS_RESPONSES		= 'responses'
NTP_SERVERS_ENTRYTYPE		= 'entrytype'

subcmds['ntpserver'] = ['default', 'defts', 'all']


#------------------------------------------------------------------------
# Routine:	main()
#
def main():
	"""
	Do everything.
	"""

	#
	# Parse the command-line arguments.
	#
	getopts()

	#
	# Get the number of log files to display.
	#
	cnt = len(loglist)

	#
	# Display each file in the list of logs.
	#
	for logname in loglist:

		#
		# Get the type of the zeek logfile.
		#
		logtype = getlogtype(logname)

		#
		# If -fields was given, we'll show all a logfile's fields
		# and exit.
		#
		if(showfields):
			showlogfields(logname, logtype)
			sys.exit(0)

		if(verbose):
			print "\"%s\" is a %s zeek logfile" % (logname, logtype.upper())

		#
		# Build a list of the fields to get from the zeek logfile.
		#
		fields = getfields(logname, logtype)

		#
		# Build a hash table of the lines in the named zeek logfile.
		#
		entrylist = getentries(logname, fields)

		#
		# Display requested information from the zeek logfile.
		#
		try:
			showentries(fields, entrylist)
		except KeyboardInterrupt:
			print "\n\n^C"
			sys.exit(0)

		#
		# If there are more log files to display, we'll print
		# a spacer line.
		#
		if(cnt > 1):
			print ""
			cnt -= 1

	sys.exit(0)


#------------------------------------------------------------------------
# Routine:	getopts()
#
def getopts():
	"""
	Parse the command line for options.
	"""
	global verbose			# Verbose flag.
	global csv			# Output in CSV format.
	global dateflag			# Send -d to zeek-cut.
	global loglist			# Names of log files.
	global filters			# Filter list from arguments.
	global showfields		# Show logfile's fields.
	global userfields		# User-specified field list.
	global usedefs			# Use default fields.

	global dnsfields		# DNS-related fields flag.
	global ntpfields		# NTP-related fields flag.
	global ntpbasefields		# NTP-base-related fields flag.
	global ntpctlfields		# NTP-ctl-related fields flag.
	global ntpm7fields		# NTP-mode7-related fields flag.
	global ntpextfields		# NTP-extensions-related fields flag.
	global ntpkissfields		# NTP-kisscode-related fields flag.
	global ntpoldfields		# NTP-old-versions-related fields flag.
	global ntpsrvrfields		# NTP-servers-related fields flag.
	global ntpstdfields		# NTP-std-related fields flag.
	global smtpfields		# SMTP-related fields flag.

	#
	# Show the usage message and exit if no options were given.
	#
	if(len(sys.argv) == 1):
		usage(1);

	#
	# Show the manpage if the -man option was given.
	# (This is done here outside of argparse since argparse wants
	# a logfile to be specified.)
	#
	if(len(sys.argv) > 1):
		if(sys.argv[1] == '-help'):
			usage(1)

		if((sys.argv[1] == '-man') or (sys.argv[1] == '-manpage')):
			manpage()

		if((sys.argv[1] == '-sub') or (sys.argv[1] == '-subcmds')):
			sys.argv.append('dummy')

	#
	# Build our usage string.
	#
	usagestr = usage(0)

	#
	# Build the options parser.
	#
	ap = argparse.ArgumentParser(add_help=False)

	#
	# Add the recognized options.
	#
	ap.add_argument('-verbose',	action='store_true')
	ap.add_argument('-Version',	action='store_true')
	ap.add_argument('-help',	action='store_true')
	ap.add_argument('-man',		action='store_true')
	ap.add_argument('-csv',		action='store_true')
	ap.add_argument('-date',	action='store_true')
	ap.add_argument('-showfields',	action='store_true')
	ap.add_argument('-logtypes',	action='store_true')
	ap.add_argument('-subcmds',	action='store')
	ap.add_argument('-usedefs',	action='store_true')

	#           
	# These options control how we'll look at the log data.
	#           

	#           
	# These are protocol-specific selection options.
	#           
	ap.add_argument('-dns',		action='store')
	ap.add_argument('-ntp',		action='store')
	ap.add_argument('-ntpbase',	action='store')
	ap.add_argument('-ntpctl',	action='store')
	ap.add_argument('-ntpm7',	action='store')
	ap.add_argument('-ntpold',	action='store')
	ap.add_argument('-ntpservers',	action='store')
	ap.add_argument('-ntpstd',	action='store')
#	ap.add_argument('-ntpext',	action='store')
	ap.add_argument('-ntpkiss',	action='store')
	ap.add_argument('-smtp',	action='store')

	#           
	# Now mix in the arguments.
	#           
	ap.add_argument('-fields',	action='append')
	ap.add_argument('-filters',	action='append')
	ap.add_argument('loglist',	nargs=argparse.REMAINDER)

	#
	# Now parse the options.
	#
	args = ap.parse_args()

	#
	# Check for some immediate options.
	#
	if(args.Version):		version()
	if(args.help):			usage(1)
	if(args.man):			manpage()
	if(args.verbose):		verbose = 1
	if(args.csv):			csv = True
	if(args.date):			dateflag = True
	if(args.usedefs):		usedefs = True
	if(args.showfields):		showfields = True
	if(args.logtypes):		showlogtypes()
	if(args.subcmds):		showsubcmds(args.subcmds)

	#
	# Get the list of user-selected fields.
	#
	if(args.fields):
		userfields = args.fields[0].split(',')

	#
	# Build the filters list of hashes.
	#	key   - logfile field name
	#	value - value to filter for
	#
	if(args.filters):
		filters = {}

		#
		# For each filter in the filters list, we'll add an
		# entry to the field's sublist.
		#
		for filt in args.filters:
			#
			# Break the filter line into two pieces.
			#
			atoms = filt.split('=')
			if(len(atoms) != 2):
				print "invalid filter - \"%s\"" % filt
				sys.exit(10)

			#
			# If this field hasn't had a filter entry yet,
			# we'll add a new filter sublist for it.
			# If this field has had a filter, we'll append
			# this filter value to its list.
			#
			if(filters.has_key(atoms[0]) == False):
				filters[atoms[0]] = [atoms[1]]
			else:
				filters[atoms[0]].append(atoms[1])


	#
	# Get shorthand holders for some options.
	#
	loglist		= args.loglist
	dnsfields	= args.dns
	ntpfields	= args.ntp
	ntpbasefields	= args.ntpbase
	ntpctlfields	= args.ntpctl
	ntpm7fields	= args.ntpm7
#	ntpextfields	= args.ntpext
	ntpkissfields	= args.ntpkiss
	ntpoldfields	= args.ntpold
	ntpsrvrfields	= args.ntpservers
	ntpstdfields	= args.ntpstd
	smtpfields	= args.smtp

	#
	# Ensure a logfile was given.
	#
	if((loglist == None) or (loglist == [])):
		print "at least one log file must be specified\n"
		usage(1)
		sys.exit(0)

#	if(verbose):
#		print "log files  - \"%s\"" % loglist
#		print "\n"


#------------------------------------------------------------------------
# Routine:	getlogtype()
#
def getlogtype(logfn):
	"""
	Return the type of a zeek log.  This is determined by the value
	of the first #path line in the file.
	"""

	logtype = 'unknown'			# Type of zeek logfile.

	#
	# Find the first #path line in the zeek log and get the line's value.
	#
	try:
		#
		# Open the log file for reading.
		#
		logfd = open(logfn, 'rU')

		#
		# Use zeek-cut to read the required fields from the log.
		#
		for ln in logfd.readlines():
			if(ln.startswith("#path")):
				atoms = ln.split("\t")
				logtype = atoms[1].strip()

				break

		logfd.close()

	#
	# Handle OSErrors -- most likely an unrecognized command.
	#
	except OSError as exc:
		print(exc.strerror)
		print "unable to get log type from \"%s\"" % logfn
		sys.exit(1);

	except IOError as exc:
		print "%s:  %s" % (logfn, exc.strerror)
		sys.exit(1);

	return(logtype)


#------------------------------------------------------------------------
# Routine:	getlogfields()
#
def getlogfields(logfn, logtype):
	"""
	Return some details of a zeek logfile.  The names and types of the fields will be returned, as well as the length of the longest field name.
	"""

	fnames = None				# Names of logfile's fields.
	ftypes = None				# Types of logfile's fields.
	maxlen = -1				# Maximum name length.

	try:
		#
		# Open the log file for reading.
		#
		logfd = open(logfn, 'rU')

		#
		# Get the fields and types lines from the logfile.
		# Split them into their atoms and drop out when we've got both.
		#
		for ln in logfd.readlines():
			ln = ln.strip()

			if(ln.startswith("#fields")):
				fnames = ln.split("\t")
				fnames.pop(0)

			elif(ln.startswith("#types")):
				ftypes = ln.split("\t")
				ftypes.pop(0)

			if((fnames != None) and (ftypes != None)):
				break

		logfd.close()

	#
	# Handle OSErrors -- most likely bad file permissions.
	#
	except OSError as exc:
		print(exc.strerror)
		print "unable to get log fields from \"%s\"" % logfn
		sys.exit(1);

	#
	# Drop out if the file has no known fields.
	#
	if(fnames == None):
		print "%s has no unknown fields; is this really a zeek logfile?" % logfn
		sys.exit(2);

	#
	# Find the length of the longest name.
	#
	for ind in range(len(fnames)):
		nl = len(fnames[ind])
		if(nl > maxlen):
			maxlen = nl

	#
	# Give our caller what their heart's desire.
	#
	return(maxlen, fnames, ftypes)


#------------------------------------------------------------------------
# Routine:	showlogfields()
#
def showlogfields(logfn, logtype):
	"""
	Show the field names of a zeek logfile.  The fields' types will
	also be shown.
	"""

	(maxlen, fnames, ftypes) = getlogfields(logfn, logtype)

	#
	# Print a tidy list of the field names and types.
	#
	for ind in range(len(fnames)):
		print "%-*s    %s" % (maxlen, fnames[ind], ftypes[ind])


#------------------------------------------------------------------------
# Routine:	showlogtypes()
#
def showlogtypes():
	"""
	Show the types of supported zeek log files.
	"""

	global subcmds				# Option subcommands.

	for proto in sorted(logtypes):
		print proto

	exit(0)


#------------------------------------------------------------------------
# Routine:	showsubcmds()
#
def showsubcmds(proto):
	"""
	Show the subcommands for a specified protocol.
	"""

	global subcmds				# Option subcommands.

	#
	# If "all" or nothing was given to -subcmds, show all the supported
	# protocols and their subcommands.
	#
	if((proto == 'all') or (proto == 'dummy')):
		for proto in sorted(subcmds):
			scstr = ", ".join(subcmds[proto])
			print "%s:  %s\n" % (proto, scstr)

		exit(0)

	#
	# Ensure that we know this protocol.
	#
	if(subcmds.has_key(proto) == False):
		print "\"%s\" is not a supported protocol" % proto
		sys.exit(0)

	#
	# Print the list of this protocol's subcommands.
	#
	print "subcommands for %s:" % proto
	for scmd in subcmds[proto]:
		print "\t%s" % scmd

	exit(0)


#----------------------------------------------------------------------
# Routine:	getfields()
#
def getfields(logname, logtype):
	"""
	Get fields to retrieve, based on the arguments we were given.

	When adding new data-selection options, getfields() is the critical
	thing that needs to be modified.  Sure, the documentation needs to
	be updated, and the new option must also be added.  However, the
	fields selected by each option are specified in getfields().  Format
	and display of the data are handled generically.

	"""

	global filters			# Filter list from arguments.
	global dnsfields		# DNS-related fields flag.
	global ntpfields		# NTP-related fields flag.
	global ntpbasefields		# NTP-base-related fields flag.
	global ntpctlfields		# NTP-ctl-related fields flag.
	global ntpm7fields		# NTP-mode7-related fields flag.
	global ntpextfields		# NTP-extensions-related fields flag.
	global ntpkissfields		# NTP-kisscode-related fields flag.
	global ntpoldfields		# NTP-old-versions-related fields flag.
	global ntpsrvrfields		# NTP-servers-related fields flag.
	global ntpstdfields		# NTP-std-related fields flag.
	global smtpfields		# SMTP-related fields flag.

	fields = None			# Fields to display.

	#
	# Set the overall default fields.  If nothing else is recognized or
	# selected, at the very least the entry timestamps will be displayed.
	#
	fields = [
			'ts'
		 ]

	#------------------------------------------------------------
	# Handle DNS logs.
	#
	if(logtype == 'dns'):

		#
		# If -dns wasn't given, use the default DNS fields.
		#
		if(dnsfields == None):
			dnsfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in dnsfields):
			[dnsfields, opts] = dnsfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of dnsfields.
		# The valid values are:
		#	default
		#	defts
		#	query
		#	flags
		#	times
		#	all
		#
		if(dnsfields == 'default'):	# Default DNS fields.
			fields = [
					DNS_ORIGHOST,
					DNS_RESPHOST,
					DNS_QUERY,
					DNS_QTYPE_NAME,
					DNS_ANSWERS
				 ]

		elif(dnsfields == 'defts'):	# DNS default + time.
			fields = [
					DNS_TS,
					DNS_ORIGHOST,
					DNS_RESPHOST,
					DNS_QUERY,
					DNS_QTYPE_NAME,
					DNS_ANSWERS
				 ]

		elif(dnsfields == 'query'):	# DNS query fields.
			fields = [
					DNS_ORIGHOST,
					DNS_QUERY,
					DNS_QCLASS_NAME,
					DNS_QTYPE_NAME,
					DNS_RCODE_NAME,
					DNS_ANSWERS
				 ]

		elif(dnsfields == 'flags'):	# DNS flag fields.
			fields = [
					DNS_TS,
					DNS_UID,
					DNS_ORIGHOST,
					DNS_RESPHOST,
					DNS_TRANS_ID,
					DNS_QUERY,
					DNS_QCLASS_NAME,
					DNS_QTYPE_NAME,
					DNS_RCODE_NAME,
					DNS_AA,
					DNS_TC,
					DNS_RD,
					DNS_RA,
					DNS_Z,
					DNS_ANSWERS,
					DNS_REJECTED
				 ]

		elif(dnsfields == 'times'):	# DNS flag fields.
			fields = [
					DNS_TS,
					DNS_UID,
					DNS_ORIGHOST,
					DNS_RESPHOST,
					DNS_RTT,
					DNS_TTLS
				 ]

		elif(dnsfields == 'all'):	# All DNS fields.
			fields = [
					DNS_TS,
					DNS_UID,
					DNS_ORIGHOST,
					DNS_ORIGPORT,
					DNS_RESPHOST,
					DNS_RESPPORT,
					DNS_PROTO,
					DNS_TRANS_ID,
					DNS_RTT,
					DNS_QUERY,
					DNS_QCLASS,
					DNS_QCLASS_NAME,
					DNS_QTYPE,
					DNS_QTYPE_NAME,
					DNS_RCODE,
					DNS_RCODE_NAME,
					DNS_AA,
					DNS_TC,
					DNS_RD,
					DNS_RA,
					DNS_Z,
					DNS_ANSWERS,
					DNS_TTLS,
					DNS_REJECTED
				 ]

		else:
			print "unknown -dns option:  \"%s\"" % dnsfields
			exit(50)

	#------------------------------------------------------------
	# Handle SMTP logs.
	#
	elif(logtype == 'smtp'):

		#
		# If -smtp wasn't given, use the default SMTP fields.
		#
		if(smtpfields == None):
			smtpfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in smtpfields):
			[smtpfields, opts] = smtpfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of smtpfields.
		# The valid values are:
		#	default
		#	defts
		#	all
		#	sender
		#	recipient (recip)
		#	names
		#	just names
		#
		if(smtpfields == 'default'):	# Default SMTP fields.
			fields = [
					SMTP_MAILFROM,
					SMTP_RCPTTO,
					SMTP_FROM,
					SMTP_TO,
					SMTP_CC,
					SMTP_REPLY_TO,
					SMTP_DATE,
					SMTP_SUBJECT
				 ]

		elif(smtpfields == 'defts'):	# SMTP default + time.
			fields = [
					SMTP_TS,
					SMTP_MAILFROM,
					SMTP_RCPTTO,
					SMTP_FROM,
					SMTP_TO,
					SMTP_CC,
					SMTP_REPLY_TO,
					SMTP_DATE,
					SMTP_SUBJECT
				 ]

		elif(smtpfields == 'sender'):	# SMTP sender fields.
			fields = [
					SMTP_ORIGHOST,
					SMTP_RESPHOST,
					SMTP_HELO,
					SMTP_FROM,
					SMTP_MAILFROM,
					SMTP_REPLY_TO
				 ]

		elif((smtpfields == 'recipient') or	# SMTP recipient fields.
		     (smtpfields == 'recip')):
			fields = [
					SMTP_ORIGHOST,
					SMTP_RESPHOST,
					SMTP_RCPTTO,
					SMTP_TO,
					SMTP_CC,
					SMTP_IN_REPLY_TO
				 ]

		elif(smtpfields == 'names'):	# SMTP sender/receiver fields.
			fields = [
					SMTP_ORIGHOST,
					SMTP_RESPHOST,
					SMTP_HELO,
					SMTP_FROM,
					SMTP_MAILFROM,
					SMTP_REPLY_TO,
					SMTP_RCPTTO,
					SMTP_TO,
					SMTP_CC,
					SMTP_IN_REPLY_TO
				 ]

		elif(smtpfields == 'justnames'): # SMTP sender/receiver fields.
			fields = [
					SMTP_HELO,
					SMTP_FROM,
					SMTP_MAILFROM,
					SMTP_REPLY_TO,
					SMTP_RCPTTO,
					SMTP_TO,
					SMTP_CC,
					SMTP_IN_REPLY_TO
				 ]

		elif(smtpfields == 'all'):	# All SMTP fields.
			fields = [		
					SMTP_TS,
					SMTP_UID,
					SMTP_ORIGHOST,
					SMTP_ORIGPORT,
					SMTP_RESPHOST,
					SMTP_RESPPORT,
					SMTP_TRANS_DEPTH,
					SMTP_HELO,
					SMTP_MAILFROM,
					SMTP_RCPTTO,
					SMTP_DATE,
					SMTP_FROM,
					SMTP_TO,
					SMTP_CC,
					SMTP_REPLY_TO,
					SMTP_MSG_ID,
					SMTP_IN_REPLY_TO,
					SMTP_SUBJECT,
					SMTP_X_ORIGINATING_IP,
					SMTP_FIRST_RECEIVED,
					SMTP_SECOND_RECEIVED,
					SMTP_LAST_REPLY,
					SMTP_PATH,
					SMTP_USER_AGENT,
					SMTP_TLS,
					SMTP_FUIDS
				 ]


		else:
			print "unknown -smtp option:  \"%s\"" % smtpfields
			exit(50)

	#------------------------------------------------------------
	# Handle NTP logs.
	#
	elif(logtype == 'ntp'):

		#
		# If -ntp wasn't given, use the default NTP fields.
		#
		if(ntpfields == None):
			ntpfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in ntpfields):
			[ntpfields, opts] = ntpfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of ntpfields.
		# The valid values are:
		#	default
		#	defts
		#	all
		#	times
		#	stats
		#
		if(ntpfields == 'default'):	# Default NTP fields.

			fields = [
					NTP_ORIGHOST,
					NTP_RESPHOST,
					NTP_STRATUM,
					NTP_MODE
				 ]

		elif(ntpfields == 'defts'):	# NTP default + time.

			fields = [
					NTP_TS,
					NTP_ORIGHOST,
					NTP_RESPHOST,
					NTP_STRATUM,
					NTP_MODE
				 ]

		elif(ntpfields == 'times'):	# NTP time fields.

			fields = [
					NTP_ORIGHOST,
					NTP_RESPHOST,
					NTP_MODENAME,
					NTP_PRECISION,
					NTP_REF_T,
					NTP_ORIGINATE_T,
					NTP_RECEIVE_T,
					NTP_XMIT_T
				 ]

		elif(ntpfields == 'stats'):	# NTP statistics fields.

			fields = [
					NTP_ORIGHOST,
					NTP_RESPHOST,
					NTP_STRATUM,
					NTP_MODE,
					NTP_POLL,
					NTP_PRECISION,
					NTP_DELAY
				 ]

		elif(ntpfields == 'all'):	# All NTP data.

			fields = [
					NTP_TS,
					NTP_UID,
					NTP_ORIGHOST,
					NTP_ORIGPORT,
					NTP_RESPHOST,
					NTP_RESPPORT,
					NTP_VERSION,
					NTP_MODE,
					NTP_STRATUM,
					NTP_POLL,
					NTP_PRECISION,
					NTP_DELAY,
					NTP_DISPERSION,
					NTP_REFID,
					NTP_REF_T,
					NTP_ORIGINATE_T,
					NTP_RECEIVE_T,
					NTP_XMIT_T,
					NTP_NUMEXTS
				]

		else:
			print "unknown -ntp option:  \"%s\"" % ntpfields
			exit(50)

	#------------------------------------------------------------
	# Handle NTP-base logs.
	#
	elif((logtype == 'ntp-base') or
	     (logtype == 'ntp-std')):

		#
		# Set up for sharing this code between -ntpbase and -ntpstd.
		#
		if(logtype == 'ntp-base'):
			optlab = "-ntpbase"
			ntpsharedfields = ntpbasefields
		else:
			optlab = "-ntpstd"
			ntpsharedfields = ntpstdfields

		#
		# If -ntpbase/-ntpstd wasn't given, use the default NTP-base
		# fields.
		#
		if(ntpsharedfields == None):
			ntpsharedfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in ntpsharedfields):
			[ntpsharedfields, opts] = ntpsharedfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of ntpsharedfields.
		# The valid values are:
		#	default
		#	defts
		#	all
		#	times
		#	stats
		#
		if(ntpsharedfields == 'default'):	# Default NTP fields.

			fields = [
					NTP_BASE_ORIGHOST,
					NTP_BASE_RESPHOST,
					NTP_BASE_STRATUMNAME,
					NTP_BASE_MODENAME
				 ]

		elif(ntpsharedfields == 'defts'):	# NTP default + time.

			fields = [
					NTP_BASE_TS,
					NTP_BASE_ORIGHOST,
					NTP_BASE_RESPHOST,
					NTP_BASE_STRATUMNAME,
					NTP_BASE_MODENAME
				 ]

		elif(ntpsharedfields == 'times'):	# NTP time fields.

			fields = [
					NTP_BASE_ORIGHOST,
					NTP_BASE_RESPHOST,
					NTP_BASE_MODENAME,
					NTP_BASE_PRECISION,
					NTP_BASE_REF_T,
					NTP_BASE_ORIGINATE_T,
					NTP_BASE_RECEIVE_T,
					NTP_BASE_XMIT_T
				 ]

		elif(ntpsharedfields == 'stats'):	# NTP statistics fields.

			fields = [
					NTP_BASE_ORIGHOST,
					NTP_BASE_RESPHOST,
					NTP_BASE_STRATUMNAME,
					NTP_BASE_MODENAME,
					NTP_BASE_POLL,
					NTP_BASE_PRECISION,
					NTP_BASE_DELAY
				 ]

		elif(ntpsharedfields == 'stratum'):	# NTP stratum fields.

			fields = [
					NTP_BASE_ORIGHOST,
					NTP_BASE_RESPHOST,
					NTP_BASE_MODE,
					NTP_BASE_STRATUM,
					NTP_BASE_STRATUMNAME,
					NTP_BASE_KISSCODE,
					NTP_BASE_REFID,
					NTP_BASE_REFADDR
				 ]

		elif(ntpsharedfields == 'all'):		# All NTP data.

			fields = [
					NTP_BASE_TS,
					NTP_BASE_UID,
					NTP_BASE_ORIGHOST,
					NTP_BASE_ORIGPORT,
					NTP_BASE_RESPHOST,
					NTP_BASE_RESPPORT,
					NTP_BASE_VERSION,
					NTP_BASE_MODE,
					NTP_BASE_MODENAME,
					NTP_BASE_STRATUM,
					NTP_BASE_STRATUMNAME,
					NTP_BASE_POLL,
					NTP_BASE_PRECISION,
					NTP_BASE_DELAY,
					NTP_BASE_DISPERSION,
					NTP_BASE_KISSCODE,
					NTP_BASE_REFID,
					NTP_BASE_REFADDR,
					NTP_BASE_REF_T,
					NTP_BASE_ORIGINATE_T,
					NTP_BASE_RECEIVE_T,
					NTP_BASE_XMIT_T,
					NTP_BASE_NUMEXTS,
					NTP_BASE_KEYID,
					NTP_BASE_DIGEST
				]

		else:
			print "unknown %s option:  \"%s\"" % (optlab, ntpsharedfields)
			exit(50)

	#------------------------------------------------------------
	# Handle NTP-ctl logs.
	#
	elif(logtype == 'ntp-ctl'):

		#
		# If -ntpctl wasn't given, use the default NTP-ctl fields.
		#
		if(ntpctlfields == None):
			ntpctlfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in ntpctlfields):
			[ntpctlfields, opts] = ntpctlfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of ntpctlfields.
		# The valid values are:
		#	default
		#	defts
		#	all
		#	crypto
		#	data
		#
		if(ntpctlfields == 'default'):	# Default NTP fields.

			fields = [
					NTP_CTL_ORIGHOST,
					NTP_CTL_RESPHOST,
					NTP_CTL_OPCODENAME,
					NTP_CTL_RESPBIT,
					NTP_CTL_ERRBIT,
					NTP_CTL_MOREBIT,
					NTP_CTL_SEQUENCE,
					NTP_CTL_ASSOCID,
					NTP_CTL_STATUS
				 ]

		elif(ntpctlfields == 'defts'):	# NTP default + time.

			fields = [
					NTP_CTL_TS,
					NTP_CTL_ORIGHOST,
					NTP_CTL_RESPHOST,
					NTP_CTL_OPCODENAME,
					NTP_CTL_RESPBIT,
					NTP_CTL_ERRBIT,
					NTP_CTL_MOREBIT,
					NTP_CTL_SEQUENCE,
					NTP_CTL_ASSOCID,
					NTP_CTL_STATUS
				 ]

		elif(ntpctlfields == 'crypto'):	# NTP crypto fields.

			fields = [
					NTP_CTL_ORIGHOST,
					NTP_CTL_RESPHOST,
					NTP_CTL_OPCODENAME,
					NTP_CTL_ASSOCID,
					NTP_CTL_KEYID,
					NTP_CTL_CRYPTO_CKSUM
				 ]

		elif(ntpctlfields == 'data'):	# NTP statistics fields.

			fields = [
					NTP_CTL_ORIGHOST,
					NTP_CTL_RESPHOST,
					NTP_CTL_OPCODENAME,
					NTP_CTL_ASSOCID,
					NTP_CTL_DATA
				 ]

		elif(ntpctlfields == 'all'):	# All NTP data.

			fields = [
					NTP_CTL_TS,
					NTP_CTL_UID,
					NTP_CTL_ORIGHOST,
					NTP_CTL_ORIGPORT,
					NTP_CTL_RESPHOST,
					NTP_CTL_RESPPORT,
					NTP_CTL_VERSION,
					NTP_CTL_MODE,
					NTP_CTL_MODENAME,
					NTP_CTL_OPCODE,
					NTP_CTL_OPCODENAME,
					NTP_CTL_RESPBIT,
					NTP_CTL_ERRBIT,
					NTP_CTL_MOREBIT,
					NTP_CTL_SEQUENCE,
					NTP_CTL_STATUS,
					NTP_CTL_ASSOCID,
					NTP_CTL_KEYID,
					NTP_CTL_CRYPTO_CKSUM,
					NTP_CTL_DATA
				 ]

		else:
			print "unknown -ntpctl option:  \"%s\"" % ntpctlfields
			exit(50)

	#------------------------------------------------------------
	# Handle NTP-mode7 logs.
	#
	elif(logtype == 'ntp-mode7'):

		#
		# If -ntpctl wasn't given, use the default NTP-mode7 fields.
		#
		if(ntpm7fields == None):
			ntpm7fields = 'default'

		#
		# Look for optional options.
		#
		if(':' in ntpm7fields):
			[ntpm7fields, opts] = ntpm7fields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of ntpm7fields.
		# The valid values are:
		#	default
		#	defts
		#	all
		#	data
		#
		if(ntpm7fields == 'default'):	# Default NTP fields.

			fields = [
					NTP_MODE7_ORIGHOST,
					NTP_MODE7_RESPHOST,
					NTP_MODE7_REQCODE,
					NTP_MODE7_SEQUENCE,
					NTP_MODE7_IMPLEMENTATION,
					NTP_MODE7_ERROR
				 ]

		elif(ntpm7fields == 'defts'):	# NTP default + time.

			fields = [
					NTP_MODE7_TS,
					NTP_MODE7_ORIGHOST,
					NTP_MODE7_RESPHOST,
					NTP_MODE7_REQCODE,
					NTP_MODE7_SEQUENCE,
					NTP_MODE7_IMPLEMENTATION,
					NTP_MODE7_ERROR
				 ]

		elif(ntpm7fields == 'data'):	# NTP statistics fields.

			fields = [
					NTP_MODE7_ORIGHOST,
					NTP_MODE7_RESPHOST,
					NTP_MODE7_REQCODE,
					NTP_MODE7_SEQUENCE,
					NTP_MODE7_DATA
				 ]

		elif(ntpm7fields == 'all'):	# All NTP data.

			fields = [
					NTP_MODE7_TS,
					NTP_MODE7_UID,
					NTP_MODE7_ORIGHOST,
					NTP_MODE7_ORIGPORT,
					NTP_MODE7_RESPHOST,
					NTP_MODE7_RESPPORT,
					NTP_MODE7_VERSION,
					NTP_MODE7_MODE,
					NTP_MODE7_MODENAME,
					NTP_MODE7_REQCODE,
					NTP_MODE7_AUTHBIT,
					NTP_MODE7_SEQUENCE,
					NTP_MODE7_IMPLEMENTATION,
					NTP_MODE7_ERROR,
					NTP_MODE7_DATA
				 ]

		else:
			print "unknown -ntpctl option:  \"%s\"" % ntpm7fields
			exit(50)

	#------------------------------------------------------------
	# Handle NTP extensions logs.
	#
	elif(logtype == 'ntp-extensions'):

		#
		# If -ntpext wasn't given, use the default NTP extensions
		# fields.
		#
		if(ntpextfields == None):
			ntpextfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in ntpextfields):
			[ntpextfields, opts] = ntpextfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of ntpextfields.
		# The valid values are:
		#	default
		#	defts
		#	data
		#	all
		#
		if(ntpextfields == 'default'):	# Default NTP extensions fields.

			fields = [
					NTP_EXT_ORIGHOST,
					NTP_EXT_RESPHOST,
					NTP_EXT_STRATUMNAME,
					NTP_EXT_ENTRYTYPE
				 ]

		elif(ntpextfields == 'defts'):	# NTP extensions default + time.

			fields = [
					NTP_EXT_TS,
					NTP_EXT_ORIGHOST,
					NTP_EXT_RESPHOST,
					NTP_EXT_STRATUMNAME,
					NTP_EXT_ENTRYTYPE
				 ]

		elif(ntpextfields == 'data'):	# NTP extensions data.

			fields = [
					NTP_EXT_ORIGHOST,
					NTP_EXT_RESPHOST,
					NTP_EXT_STRATUMNAME,
					NTP_EXT_EXCESSLEN,
					NTP_EXT_FIELDTYPE,
					NTP_EXT_EXTLEN,
					NTP_EXT_ENTRYTYPE
				 ]

		elif(ntpextfields == 'all'):	# All NTP extensions data.

			fields = [
					NTP_EXT_TS,
					NTP_EXT_UID,
					NTP_EXT_ORIGHOST,
					NTP_EXT_ORIGPORT,
					NTP_EXT_RESPHOST,
					NTP_EXT_RESPPORT,
					NTP_EXT_PROTO,
					NTP_EXT_STRATUM,
					NTP_EXT_STRATUMNAME,
					NTP_EXT_EXCESSLEN,
					NTP_EXT_FIELDTYPE,
					NTP_EXT_EXTLEN,
					NTP_EXT_ENTRYTYPE
				 ]


		else:
			print "unknown -ntpext option:  \"%s\"" % ntpextfields
			exit(50)

	#------------------------------------------------------------
	# Handle NTP kiss-code/ref-id logs.
	#
	elif(logtype == 'ntp-kisscode'):

		#
		# If -ntpkiss wasn't given, use the default NTP extensions
		# fields.
		#
		if(ntpkissfields == None):
			ntpkissfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in ntpkissfields):
			[ntpkissfields, opts] = ntpkissfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of ntpkissfields.
		# The valid values are:
		#	default
		#	defts
		#	data
		#	all
		#
		if(ntpkissfields == 'default'):	# Default NTP kisscode fields.

			fields = [
					NTP_KISS_ORIGHOST,
					NTP_KISS_RESPHOST,
					NTP_KISS_MODENAME,
					NTP_KISS_STRATUMNAME,
					NTP_KISS_KISSCODE,
					NTP_KISS_REFID
				 ]

		elif(ntpkissfields == 'defts'):	# NTP kisscode default + time.

			fields = [
					NTP_KISS_TS,
					NTP_KISS_ORIGHOST,
					NTP_KISS_RESPHOST,
					NTP_KISS_MODENAME,
					NTP_KISS_STRATUMNAME,
					NTP_KISS_KISSCODE,
					NTP_KISS_REFID
				 ]

		elif(ntpkissfields == 'data'):	# NTP kisscode data.

			fields = [
					NTP_KISS_ORIGHOST,
					NTP_KISS_RESPHOST,
					NTP_KISS_MODE,
					NTP_KISS_STRATUM,
					NTP_KISS_KISSCODE,
					NTP_KISS_REFID
				 ]

		elif(ntpkissfields == 'all'):	# All NTP kisscode data.

			fields = [
					NTP_KISS_TS,
					NTP_KISS_UID,
					NTP_KISS_ORIGHOST,
					NTP_KISS_ORIGPORT,
					NTP_KISS_RESPHOST,
					NTP_KISS_RESPPORT,
					NTP_KISS_MODE,
					NTP_KISS_MODENAME,
					NTP_KISS_STRATUM,
					NTP_KISS_STRATUMNAME,
					NTP_KISS_KISSCODE,
					NTP_KISS_REFID
				 ]


		else:
			print "unknown -ntpkiss option:  \"%s\"" % ntpkissfields
			exit(50)

	#------------------------------------------------------------
	# Handle NTP old-versions logs.
	#
	elif(logtype == 'ntp-oldversions'):

		#
		# If -ntpold wasn't given, use the default NTP old-versions
		# fields.
		#
		if(ntpoldfields == None):
			ntpoldfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in ntpoldfields):
			[ntpoldfields, opts] = ntpoldfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of ntpoldfields.
		# The valid values are:
		#	default
		#	defts
		#	all
		#
		if(ntpoldfields == 'default'):	# Def. NTP old-versions fields.

			fields = [
					NTP_OLDVERS_ORIGHOST,
					NTP_OLDVERS_RESPHOST,
					NTP_OLDVERS_VERSION,
					NTP_OLDVERS_MODENAME,
					NTP_OLDVERS_STRATUMNAME
				 ]

		elif(ntpoldfields == 'defts'):	# NTP old-vers default + time.

			fields = [
					NTP_OLDVERS_TS,
					NTP_OLDVERS_ORIGHOST,
					NTP_OLDVERS_RESPHOST,
					NTP_OLDVERS_VERSION,
					NTP_OLDVERS_MODENAME,
					NTP_OLDVERS_STRATUMNAME
				 ]

		elif(ntpoldfields == 'all'):	# All NTP old-versions data.

			fields = [
					NTP_OLDVERS_TS,
					NTP_OLDVERS_UID,
					NTP_OLDVERS_ORIGHOST,
					NTP_OLDVERS_ORIGPORT,
					NTP_OLDVERS_RESPHOST,
					NTP_OLDVERS_RESPPORT,
					NTP_OLDVERS_PROTO,
					NTP_OLDVERS_VERSION,
					NTP_OLDVERS_MODE,
					NTP_OLDVERS_MODENAME,
					NTP_OLDVERS_STRATUM,
					NTP_OLDVERS_STRATUMNAME
				 ]

		else:
			print "unknown -ntpold option:  \"%s\"" % ntpoldfields
			exit(50)

	#------------------------------------------------------------
	# Handle NTP servers logs.
	#
	elif(logtype == 'ntp-servers'):

		#
		# If -ntpold wasn't given, use the default NTP servers fields.
		#
		if(ntpsrvrfields == None):
			ntpsrvrfields = 'default'

		#
		# Look for optional options.
		#
		if(':' in ntpsrvrfields):
			[ntpsrvrfields, opts] = ntpsrvrfields.split(':')
		else:
			opts = None

		#
		# Set the fields based on the value of ntpsrvrfields.
		# The valid values are:
		#	default
		#	defts
		#	all
		#
		if(ntpsrvrfields == 'default'):	# Def. NTP servers fields.

			fields = [
					NTP_SERVERS_HADDR,
					NTP_SERVERS_STRATUMNAME,
					NTP_SERVERS_RESPONSES,
					NTP_SERVERS_ENTRYTYPE
				 ]

		elif(ntpsrvrfields == 'defts'):	# NTP servers default + time.

			fields = [
					NTP_SERVERS_TS,
					NTP_SERVERS_HADDR,
					NTP_SERVERS_STRATUMNAME,
					NTP_SERVERS_RESPONSES,
					NTP_SERVERS_ENTRYTYPE
				 ]

		elif(ntpsrvrfields == 'all'):	# All NTP servers data.

			fields = [
					NTP_SERVERS_TS,
					NTP_SERVERS_HADDR,
					NTP_SERVERS_STRATUM,
					NTP_SERVERS_STRATUMNAME,
					NTP_SERVERS_RESPONSES,
					NTP_SERVERS_ENTRYTYPE
				 ]

		else:
			print "unknown -ntpserver option:  \"%s\"" % ntpsrvrfields
			exit(50)

	#------------------------------------------------------------
	# This is the catch-all for those log files we aren't explicitly
	# supporting yet.
	#
	else:
		(maxlen, fields, ftypes) = getlogfields(logname, logtype)

		opts = None


	#
	# Add the optional options to the end of the fields list.
	#
	if(opts != None):
		for opt in opts.split(','):
			fields.append(opt)


	#
	# Stir in the user-specified fields to the fields list.
	# If the -usedefs option was given, then we'll add the user fields
	# to the end of the fields list.
	# If -usedefs wasn't given, then the user fields will be the only
	# fields added to the fields list.
	#
	if(userfields != None):
		if(usedefs):
			fields.extend(userfields)
		else:
			fields = userfields

	#
	# Delete filters whose field keys aren't in the fields list.
	# If we delete all the filters, we'll reset the filters list.
	#
	if(filters != None):
		for fld in filters.keys():
			if(fld not in fields):
				filters.pop(fld)

		if(len(filters.keys()) == 0):
			filters = None


	return(fields)


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
		if(ln.startswith('#') == True):
			continue
		ln = ln.strip()

		#
		# Split the line into its constituent atoms.
		#
		atoms = ln.split("\t")

		if(fcnt > len(atoms)):
			print "more fields were requested than were returned;"
			print "this implies an invalid field was specified" 
			exit(30)

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
# Routine:	getentries()
#
def getentries(logfn, fields):
	"""
	Get the entries from a zeek log and put them into a list of hashed
	entries.  The keys to the hash are the strings in the fields argument.
	The list is then returned.
	"""

	global dateflag				# Send -d to zeek-cut.

	lines = []				# Contents of the log file.
	fieldlist = []				# Hashed lines.

	#
	# Build the zeek-cut command line we'll need.
	# If the -d option was given, we'll pass it along to zeek-cut.
	#
	cmdline = [ZEEKCUT]
	if(dateflag):
		cmdline.append("-d")
	cmdline.extend(fields)

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
		print "%s failed:  %s" % (ZEEKCUT, exc)
		sys.exit(1);

	#
	# Handle CalledProcessErrors -- errors with zeek-cut.
	#
	except subprocess.CalledProcessError as exc:
		retcode = exc.returncode;
		print "%s errors:  %s" % (NAME, exc)
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


#------------------------------------------------------------------------
# Routine:	showentries()
#
def showentries(fields, entrylist):
	"""
	Show the selected data from each SMTP log entry.  The selections
	are indicated in the fields argument, and the actual data are in
	the entrylist argument.  Output is given in the order of the
	fields list.

	Arguments:
		fields		List of field names, as recognized by zeek-cut.

		entrylist	List of hashed data from the SMTP zeek log.
				The hash keys are matched in the fields array.

	The fields are restricted to showing no more than MAXSTRLEN
	characters per line.
	"""

	cnt = 0			# Count of remote requestors we've found.
	out = ''		# Output buffer of matching entries.
	maxlens = {}		# Maximum lengths of data columns.

	#
	# Build a header list, which will be uppercase versions of field names.
	#
	headers = [hdr.upper() for hdr in fields]

	#
	# Don't complain if the user ctrl-C's out.
	#
	signal(SIGPIPE, SIG_DFL)

	#
	# If the user wants CSV, we'll build the nice simple CSV output.
	# Otherwise, we'll build columnar output, which spaces everything
	# out in nice, easy-to-read, fixed-length columns.
	#
	if(csv == True):
		#
		# Set up the header line.
		#
		out = ','.join(headers) + "\n"

		#
		# Add the unfiltered entries to the output.
		#
		for entry in entrylist:
			ln = ''			# Line buffer for building.
			use = 0			# Use-line flag.

			#
			# Add the field to the line buffer.  We'll also
			# check to see if this field causes any filtering.
			#
			for field in fields:
				ln += entry[field] + ","
				if(filteron(field, entry[field]) == True):
					use += 1

			#
			# Add this entry to the output if we should use it.
			#
			if(use > 0):
				out += ln.strip() + "\n"

			#
			# We'll only buffer 1000 lines before printing
			# everything and starting again.
			#
			if((cnt % 1000) == 0):
				print out.strip()
				out = ''

			#
			# Bump our count of displayed entries.
			#
			cnt += 1

	else:

		#
		# Initialize the maximum lengths to the values of the headers.
		#
		for ind in range(len(headers)):
			maxlens[fields[ind]] = len(headers[ind])

		#
		# Find the maximum field lengths for each of the fields in
		# each of the entries.
		#
		for entry in entrylist:
			for field in entry.keys():
				if(len(entry[field]) > maxlens[field]):
					maxlens[field] = len(entry[field])

		#
		# Enforce a maximum field length for all fields.
		#
		for k in maxlens.keys():
			if(maxlens[k] > MAXSTRLEN):
				maxlens[k] = MAXSTRLEN

		#
		# Build the header for the output.
		#
		for ind in range(len(headers)):
			out += "%-*s    " % (maxlens[fields[ind]], headers[ind])

		out = out.strip() + "\n"

		#
		# Now add each entry's fields in the proper order.
		#
		for entry in entrylist:
			ln = ''			# Line buffer for building.
			use = 0			# Use-line flag.

			#
			# Add the entry's selected fields.
			#
			for field in fields:
				str = entry[field][0:maxlens[field]]
				ln += "%-*s    " % (maxlens[field],str)

				if(filteron(field, entry[field]) == True):
					use += 1

			#
			# Add this entry to the output if we should use it.
			#
			if(use > 0):
				out += ln.strip() + "\n"

			#
			# We'll only buffer 1000 lines before printing
			# everything and starting again.
			#
			if((cnt % 1000) == 0):
				print out.strip()
				out = ''

			#
			# Bump our count of displayed entries.
			#
			cnt += 1

	#
	# If we found some SMTP log entries, print the relevant data.
	# If there weren't any, print an error message.
	#
	if(cnt != 0):
		print out.strip()

	else:
		print "no entries found in log"


#----------------------------------------------------------------------
# Routine:	filteron()
#
def filteron(field, value):
	"""
	Return a boolean indicating if the specified field indicates the
	entry should be filtered out.  This routine only returns a boolean
	indicating filter status; it's up to the calling routine to obey
	the return code.

	Each of the filter values for the filter field will be checked.
	If any of the filter values are in the specified value, the
	field will be filtered out.

	If no filters have been defined at all, we'll include this field.

	Return Values:
		True	- Filter value matches this field of the entry.
			- There are no filters, so entry *effectively* matches.

		False	- Filter value does not match entry's field.
			- There is no filter for specified field.
	"""

	#
	# If there isn't a filter for this field, allow it to pass through.
	#
	if(filters == None):
		return(True)

	#
	# If there isn't a filter for this field, allow it to pass through.
	#
	if(filters.has_key(field) == False):
		return(False)

	#
	# If the provided value contains any of this filter field's values,
	# we'll allow this field.
	#
	for fval in filters[field]:

		if(fval in value):
			return(True)

	#
	# This field does not match any filter values.
	#
	return(False)


#----------------------------------------------------------------------
# Routine:	version()
#
def version():
	"""
	Print the version number(s) and exit.
	"""
	print(VERS)
	sys.exit(0)


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
	outstr = """zeek-log [options] <logname1> ... <lognameN>

        where [options] are:

                -dns          - display DNS entries in a dns.log
                -ntp          - display NTP entries in an ntp.log
                -ntpbase      - display all NTP entries (ntp-base.log)
                -ntpctl       - display NTP control entries in an ntp-ctl.log
                -ntpm7        - display NTP mode 7 entries (ntp-mode7.log)
                -ntpkiss      - display NTP kiss-code/ref-id entries
                                (ntp-kisscode.log)
                -ntpold       - display data on use of old NTP versions
                                (ntp-oldversions.log)
                -ntpservers   - display data on NTP servers (ntp-servers.log)
                -ntpstd       - display NTP standard entries (ntp-std.log)
                -smtp         - display SMTP entries in an smtp.log

                -csv          - give output in CSV format
                -date         - translate date fields to human-readable format
                -showfields   - show field names and types of a zeek logfile
		-logfiles     - show the supported zeek log files
                -subcmds      - show option subcommands for a specified protocol

                -filter       - define a selection filter
                -fields       - specify fields to display
                -usedefs      - use the default fields with user fields

                -verbose      - give verbose output
                -Version      - show version and exit
                -help         - show usage message and exit
                -man          - show manpage and exit
 """

#                -ntpext       - display NTP extensions data     (NYI)

	#
	# Just return the output if we aren't to print the usage string.
	#
	if(prtflag == 0):
		return(outstr)

	#
	# Print the usage string and exit.
	#
	print("usage:  " + outstr.rstrip())
	sys.exit(0)


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

