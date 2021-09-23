##!	ntp.zeek	Handles NTP traffic.
#
#       This plugin registers a port with zeek to handle NTP traffic, and
#	then sets up for zeek-type logging.  After this initialization,
#	data from NTP packets are logged in the normal zeek-like way.
#
#	This plugin requires zeek 3.0.0 or later.
#
#	The following actions are (possibly) taken for every NTP packet
#	received:
#		- basic values of each NTP message are logged
#
#		- use of a non-current version of NTP is logged
#
#		- messages from previously unseen NTP servers are logged
#
#		- at end of execution, final counts of messages from each
#		  NTP server are logged
#
#		- NTP extension data is logged
#		  (in progress)
#
#	The following log files are maintained:
#		- ntp-base.log		comprehensive NTP logging
#					(all packets are logged, but only
#					modes 1-5 have much detail)
#
#		- ntp-std.log		NTP standard-message logging
#					(modes 1-5)
#
#		- ntp-ctl.log		NTP control-message logging
#					(mode 6)
#
#		- ntp-mode7.log		NTP mode-7-message logging
#					(mode 7)
#
#		- ntp-extensions.log	NTP extension data logging
#					(This log is not currently being
#					created, due to lost functionality
#					when bro 2.7 moved to zeek 3.)
#
#		- ntp-kisscodes.log	NTP kiss codes from strata 0 and 1
#
#		- ntp-oldversions.log	NTP packets that use old NTP versions
#
#		- ntp-servers.log	NTP servers whose traffic has
#					been observed
#
#	Event handlers:
#		- zeek_init()
#			Initializes zeek for handling NTP packets.
#
#		- zeek_done()
#			Finalizes NTP handling (logs final message counts
#			of each server.)
#
#		- ntp_message()
#			Performs NTP-related actions (as defined above) for
#			each NTP packet seen.
#
#	Revision History
#		1.0	Initial revision.				190830
#		1.1	Added id fields to extensions log.		191001
#		1.2	Initial port of ntp.bro to ntp.zeek.		191118
#		1.3	Added separate logging of control messages.	191119
#		1.4	Added separate logging of mode-7 messages.	191119
#		1.5	Added separate logging of NTP kiss codes.	191125
#		1.6	Added support for gathering statistics.		191223
#			Statistics are simple incoming/outgoing counts
#			and incoming/outgoing counts divided by mode.
#		1.7	Additional statistics support.			191230
#		1.8	Move statistics to ntp-stats.zeek.		191231
#		1.9	Fixed how ref_id, ref_addr, and kiss_code	200121
#			are taken from NTP data.
#
#
#	This script was written for the GAWSEED project.
#


@load base/frameworks/notice

@load base/protocols/conn

module NTP;


#
# Version information.
#
const NAME    = "ntp.zeek";
const VERSION = fmt("%s version: 1.9", NAME);

#
# Flags for enabling tests.
#	test_oldversion	- Controls test code for recognizing old NTP versions.
#
const test_oldversion = F;


export
{
	#
	# Define the log files we'll be using.
	#
	redef enum Log::ID += { BASELOG, STDLOG, CTLLOG, MODE7LOG, VERSLOG, SERVERLOG, KISSLOG, EXTENSIONLOG };

	#
	# Data recorded for NTP standard messages we see.  This is all
	# the fields in the standard-message packets.
	# This is used for both ntp-base.log and ntp-std.log.
	# Extended fields are not included.
	#
	type stdinfo: record
	{
		ts:		time		&log;
		uid:		string		&log;
		id:		conn_id		&log;

		version:	count		&log;
		mode:		count		&log;
		modename:	string		&log &optional;

		#
		# The following fields are in the NTP::StandardMessage record.
		#
		stratum:	count		&log;
		stratumname:	string		&log &optional;

		poll:		interval	&log;
		precision:	interval	&log;

		root_delay:	interval	&log;
		root_disp:	interval	&log;

		kiss_code:	string		&log &optional;

		ref_id:		string		&log &optional;
		ref_addr:	addr		&log &optional;

		ref_time:	time		&log;
		org_time:	time		&log;
		rec_time:	time		&log;
		xmt_time:	time		&log;

		num_exts:	count		&log;

		key_id:		count		&log &optional;
		digest:		string		&log &optional;

	};

	#
	# Data recorded for every NTP control packet we see.  This is all
	# the fields in the basic packets; extended fields are not included.
	# This is used for both ntp-ctl.log.
	#
	type ctlinfo: record
	{
		ts:		time		&log;
		uid:		string		&log;
		id:		conn_id		&log;

		version:	count		&log;
		mode:		count		&log;
		modename:	string		&log &optional;

		#
		# The following fields are in the NTP::ControlMessage record.
		#
		opcode:		count		&log;
		opcodename:	string		&log &optional;

		respbit:	bool		&log;
		errbit:		bool		&log;
		morebit:	bool		&log;

		sequence:	count		&log;

		status:		count		&log;

		associd:	count		&log;

		data:		string		&log &optional;

		keyid:		count		&log &optional;

		crypto_cksum:	string		&log &optional;

	};

	#
	# Data recorded for every NTP mode-7 packet we see.  This is all
	# the fields in the basic packets; extended fields are not included.
	#
	type mode7info: record
	{
		ts:		time		&log;
		uid:		string		&log;
		id:		conn_id		&log;

		version:	count		&log;
		mode:		count		&log;
		modename:	string		&log &optional;

		#
		# The following fields are in the NTP::Mode7Message record.
		#
		reqcode:	count		&log;

		authbit:	bool		&log;

		sequence:	count		&log;

		impl:		count		&log;

		err:		count		&log;
		errstr:		string		&log;

		data:		string		&log &optional;

	};

	#
	# Data recorded for packets with old NTP versions.
	#
	type versinfo: record
	{
		ts:		time		&log;
		uid:		string		&log;
		id:		conn_id		&log;

		version:	count		&log;

		mode:		count		&log;
		modename:	string		&log &optional;

		stratum:	count		&log;
		stratumname:	string		&log &optional;

	};

	#
	# Data for recording observed NTP servers.
	#
	type timeserver: record
	{
		ts:		time		&log;
		haddr:		addr		&log;

		stratum:	count		&log;
		stratumname:	string		&log &optional;

		responses:	count		&log &optional;

		entrytype:	string		&log &optional;
	};

	#
	# Data recorded for NTP kiss-codes and ref-ids.
	#
	type kissinfo: record
	{
		ts:		time		&log;
		uid:		string		&log;
		id:		conn_id		&log;

		mode:		count		&log;
		modename:	string		&log &optional;

		stratum:	count		&log;
		stratumname:	string		&log &optional;

		kiss_code:	string		&log &optional;	    # Stratum 0
		ref_id:		string		&log &optional;	    # Stratum 1
	};

	#
	# Data for recording NTP extension data.
	#
	#	Due to features lost in the bro->zeek transition,
	#	this record is currently unused.
	#
	type extinfo: record
	{
		ts:		time		&log;
		uid:		string		&log;
		id:		conn_id		&log;

		stratum:	count		&log;
		stratumname:	string		&log &optional;

		excesslen:	count		&log &optional;

		fieldtype:	count		&log;
		extlen:		count		&log;

		num_exts:	count		&log;

		entrytype:	string		&log &optional;
	};

	#------------------------------------------------------------
	#
	# Constants used in NTP packets.
	#

	const CURRENT_NTP_VERSION = 4;			# Current NTP version.

	#
	# Mode values for NTP packets.
	#
	#	RFC-5905 refers to this as a mode.
	#	Zeek/bro refers to this as a code.
	#
	const NTP_MODE_RESERVED       = 0;	#  Reserved.
	const NTP_MODE_SYMACTIVE      = 1;	#  Symmetric active.
	const NTP_MODE_SYMPASSIVE     = 2;	#  Symmetric passive.
	const NTP_MODE_CLIENT         = 3;	#  Client.
	const NTP_MODE_SERVER         = 4;	#  Server.
	const NTP_MODE_BROADCAST      = 5;	#  Broadcast.
	const NTP_MODE_NTP_CTL        = 6;	#  NTP control message.
	const NTP_MODE_PRIVATE        = 7;	#  Reserved for private use.

	const modelist = [
				NTP_MODE_RESERVED,
				NTP_MODE_SYMACTIVE,
				NTP_MODE_SYMPASSIVE,
				NTP_MODE_CLIENT,
				NTP_MODE_SERVER,
				NTP_MODE_BROADCAST,
				NTP_MODE_NTP_CTL,
				NTP_MODE_PRIVATE
			 ];

	#
	# Names of mode values.
	#
	const modenames =
	{
		[0] = "reserved",
		[1] = "symmetric active",
		[2] = "symmetric passive",
		[3] = "client",
		[4] = "server",
		[5] = "broadcast",
		[6] = "NTP control message",
		[7] = "reserved private",
	};       

	#
	# Stratum values for NTP packets.
	#
	const NTP_STRATUM_UNSPECIFIED	= 0;	# Unspecified or invalid.
	const NTP_STRATUM_PRIMARY	= 1;	# Primary server.
	const NTP_STRATUM_SEC_MIN	= 2;	# Min secondary server (via NTP)
	const NTP_STRATUM_SEC_MAX	= 15;	# Max secondary server (via NTP)
	const NTP_STRATUM_UNSYNCH	= 16;	# Unsynchronized.
	const NTP_STRATUM_RES_MIN	= 17;	# Minimum reserved value.
	const NTP_STRATUM_RES_MAX	= 255;	# Maximum reserved value.

	#
	# Names of stratum values.
	#
	const STRATUM_PRIMARY_NAME	  = "Primary Server";
	const STRATUM_SECONDARY_NAME	  = "Secondary Server";
	const STRATUM_UNSYNCHRONIZED_NAME = "Unsynchronized";
	const STRATUM_RESERVED_NAME	  = "Reserved";

	#
	# Names of opcodes from control messages.
	#
	const control_opcodes =
	{
		[1] = "read status",
		[2] = "read variables",
		[3] = "write variables",
		[4] = "read clock variables",
		[5] = "write clock variables",
		[6] = "set trap address/port",
		[7] = "trap response",
	};

	#
	# Error strings for errors in mode-7 messages.
	#
	const mode7errors =
	{
		[0] = "no error",
		[1] = "incompatible implementation number",
		[2] = "unimplemented request code",
		[3] = "format error",
		[4] = "no data available",
		[5] = "unknown",
		[6] = "unknown",
		[7] = "authentication failure",
	};


	#------------------------------------------------------------
	#
	# Constants and values used by this NTP plugin.
	#

	#
	# NTP ports we'll monitor.
	#
#	const ports = { 123/udp, 123/tcp};

	#
	# List of NTP servers whose traffic we've observed.
	#
	global servers : vector of timeserver;

	#------------------------------------------------------------
	#
	# Constants defined by IANA for NTP.  These were taken from
	# https://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml
	#

	#
	# Field types for extensions.
	#	"Checksum Complement" comes from RFC7821.
	#	All others are from RFC5906.
	#
	const FT_CRYPTO_NAK	 = 0x0000;	# Crypto-NAK; (w/ fieldlen of 0)

	const FT_NOP_REQ	 = 0x0002;	# No-Operation Request
	const FT_NOP_RESP	 = 0x8002;	# No-Operation Response
	const FT_NOP_ERROR	 = 0xC002;	# No-Operation Error Response

	const FT_AM_REQ		 = 0x0102;	# Association Message Request
	const FT_AM_RESP	 = 0x8102;	# Association Message Response
	const FT_AM_ERROR	 = 0xC102;	# Association Msg Error Response

	const FT_CERT_REQ	 = 0x0202;	# Certificate Message Request
	const FT_CERT_RESP	 = 0x8202;	# Certificate Message Response
	const FT_CERT_ERROR	 = 0xC202;	# Certificate Msg Error Response

	const FT_COOKIE_REQ	 = 0x0302;	# Cookie Message Request
	const FT_COOKIE_RESP	 = 0x8302;	# Cookie Message Response
	const FT_COOKIE_ERROR	 = 0xC302;	# Cookie Msg Error Response

	const FT_AUTOKEY_REQ	 = 0x0402;	# Autokey Message Request
	const FT_AUTOKEY_RESP	 = 0x8402;	# Autokey Message Response
	const FT_AUTOKEY_ERROR	 = 0xC402;	# Autokey Msg Error Response

	const FT_LEAP_REQ	 = 0x0502;	# Leapseconds Message Request
	const FT_LEAP_RESP	 = 0x8502;	# Leapseconds Message Response
	const FT_LEAP_ERROR	 = 0xC502;	# Leapseconds Msg Error Response

	const FT_SIGN_REQ	 = 0x0602;	# Sign Message Request
	const FT_SIGN_RESP	 = 0x8602;	# Sign Message Response
	const FT_SIGN_ERROR	 = 0xC602;	# Sign Msg Error Response

	const FT_IFF_IDENT_REQ	 = 0x0702;	# IFF Identity Message Request
	const FT_IFF_IDENT_RESP	 = 0x8702;	# IFF Identity Message Response
	const FT_IFF_IDENT_ERROR = 0xC702;	# IFF Identity Msg Error Resp

	const FT_GQ_IDENT_REQ	 = 0x0802;	# GQ Identity Message Request
	const FT_GQ_IDENT_RESP	 = 0x8802;	# GQ Identity Message Response
	const FT_GQ_IDENT_ERROR  = 0xC802;	# GQ Identity Msg Error Response

	const FT_MV_IDENT_REQ	 = 0x0902;	# MV Identity Message Request
	const FT_MV_IDENT_RESP	 = 0x8902;	# MV Identity Message Response
	const FT_MV_IDENT_ERROR  = 0xC902;	# MV Identity Msg Error Response

	const FT_CHECKSUM	 = 0x2005;	# Checksum Complement

	#
	# Translation tables for field-type values to descriptions.
	#

	const fieldtype_names =
	{
		[FT_CRYPTO_NAK]		= "Crypto-NAK",

		[FT_NOP_REQ]		= "No-Operation Request",
		[FT_NOP_RESP]		= "No-Operation Response",
		[FT_NOP_ERROR]		= "No-Operation Error Response",

		[FT_AM_REQ]		= "Association Message Request",
		[FT_AM_RESP]		= "Association Message Response",
		[FT_AM_ERROR]		= "Association Message Error Response",

		[FT_CERT_REQ]		= "Certificate Message Request",
		[FT_CERT_RESP]		= "Certificate Message Response",
		[FT_CERT_ERROR]		= "Certificate Message Error Response",

		[FT_COOKIE_REQ]		= "Cookie Message Request",
		[FT_COOKIE_RESP]	= "Cookie Message Response",
		[FT_COOKIE_ERROR]	= "Cookie Message Error Response",

		[FT_AUTOKEY_REQ]	= "Autokey Message Request",
		[FT_AUTOKEY_RESP]	= "Autokey Message Response",
		[FT_AUTOKEY_ERROR]	= "Autokey Message Error Response",

		[FT_LEAP_REQ]		= "Leapseconds Message Request",
		[FT_LEAP_RESP]		= "Leapseconds Message Response",
		[FT_LEAP_ERROR]		= "Leapseconds Message Error Response",

		[FT_SIGN_REQ]		= "Sign Message Request",
		[FT_SIGN_RESP]		= "Sign Message Response",
		[FT_SIGN_ERROR]		= "Sign Message Error Response",

		[FT_IFF_IDENT_REQ]	= "IFF Identity Message Request",
		[FT_IFF_IDENT_RESP]	= "IFF Identity Message Response",
		[FT_IFF_IDENT_ERROR]	= "IFF Identity Message Error Response",

		[FT_GQ_IDENT_REQ]	= "GQ Identity Message Request",
		[FT_GQ_IDENT_RESP]	= "GQ Identity Message Response",
		[FT_GQ_IDENT_ERROR]	= "GQ Identity Message Error Response",

		[FT_MV_IDENT_REQ]	= "MV Identity Message Request",
		[FT_MV_IDENT_RESP]	= "MV Identity Message Response",
		[FT_MV_IDENT_ERROR]	= "MV Identity Message Error Response",

		[FT_CHECKSUM]		= "Checksum Complement",
	};

}

#-----------------------------------------------------------------------------
# Routine:	stratumname()
#
# Purpose:	Translate a stratum number into the associated string name.
#		This is not a simple table look-up due to the "reserved"
#		value being a range.
#
function stratumname(strat: count): string
{
	local sname = "Unspecified";		# Translated stratum name.

	#
	# Figure out the stratum name.  This isn't a straight one-to-one
	# value, since the RFC defines two ranges of values that equate
	# to a couple specific things.
	#
	if(strat == NTP_STRATUM_PRIMARY)
	{
		sname = STRATUM_PRIMARY_NAME;
	}
	else if((strat >= NTP_STRATUM_SEC_MIN) &&
	        (strat <= NTP_STRATUM_SEC_MAX))
	{
		sname = STRATUM_SECONDARY_NAME;
	}
	else if(strat == NTP_STRATUM_UNSYNCH)
	{
		sname = STRATUM_UNSYNCHRONIZED_NAME;
	}
	else if((strat >= NTP_STRATUM_RES_MIN) &&
	        (strat <= NTP_STRATUM_RES_MAX))
	{
		sname = STRATUM_RESERVED_NAME;
	}
	else if(strat == NTP_STRATUM_UNSPECIFIED)
	{
		sname = "unspecified";
	}
	else
	{
#		sname = fmt("Unspecified - %d", strat);
		sname = "Unspecified";
	}

	return(sname);
}

#-----------------------------------------------------------------------------
# Routine:	getopcodename()
#
# Purpose:	Translate a control opcode number into the associated string
#		name.
#		This is not a simple table look-up due to the "reserved"
#		value being a range.
#
function getopcodename(opcode: count): string
{
	if((opcode < 1) || (opcode > 7))
	{
		return("reserved");
	}

	return(control_opcodes[opcode]);
}

#-----------------------------------------------------------------------------
# Routine:	msg_logstd()
#
# Purpose:	This function logs the basic packet values of an NTP
#		standard message.
#
#		Log messages are written to the ntp-base.log and
#		ntp-std.log files.
#
#		Called by the ntp_message() event handler.
#
function msg_logstd(c: connection, isorig: bool, msg: NTP::Message, sname: string, stdonly: bool)
{
	local std: stdinfo;			# Standard NTP info.

	#
	# If this call is only supposed to log standard messages and this
	# is a control or mode-7 message, then we'll return now.
	#
	if((stdonly == T) && (msg$mode > 5))
	{
		return;
	}

	#
	# Build the standard info record.
	#
	std =	[
			$ts		= network_time(),
			$uid		= c$uid,
			$id		= c$id,

			$version	= msg$version,

			$mode		= msg$mode,
			$modename	= modenames[msg$mode],

			$stratum	= NTP_STRATUM_UNSPECIFIED,

			$poll		= 0min,
			$precision	= 0min,

			$root_delay	= 0min,
			$root_disp	= 0min,

			$ref_time	= current_time(),
			$org_time	= current_time(),
			$rec_time	= current_time(),
			$xmt_time	= current_time(),
			$num_exts	= 0

			#
			# Not setting these optional fields so they'll
			# appear as standard zeek unspecified fields.
			#
#			$stratumname	= "unspecified",
#			$kiss_code	= "-",
#			$ref_id		= "-",
#			$ref_addr	= 0.0.0.0,

		];

	#
	# If we have a std_msg record in the message record, we'll set
	# a bunch of fields in the standard info record.  Some of these
	# fields are required and some are optional.
	#
	# Otherwise, we'll leave the defaults in place.
	#
	if(msg?$std_msg == T)
	{
		#
		# Get a bunch of required values from the message.
		#
		std$poll	= msg$std_msg$poll;
		std$precision	= msg$std_msg$precision;

		std$root_delay	= msg$std_msg$root_delay;
		std$root_disp	= msg$std_msg$root_disp;

		std$ref_time	= msg$std_msg$ref_time;
		std$org_time	= msg$std_msg$org_time;
		std$rec_time	= msg$std_msg$rec_time;
		std$xmt_time	= msg$std_msg$xmt_time;

		std$num_exts	= msg$std_msg$num_exts;

		#
		# Set the stratumname according to the stratum number.
		#
		std$stratumname = stratumname(msg$std_msg$stratum);


		#
		# Now we'll pick up the optional values from the message.
		#

		if(msg$std_msg?$kiss_code == T)
		{
			std$kiss_code = msg$std_msg$kiss_code;
		}

		if(msg$std_msg?$ref_id == T)
		{
			std$ref_id = msg$std_msg$ref_id;
		}

		if(msg$std_msg?$ref_addr == T)
		{
			std$ref_addr = msg$std_msg$ref_addr;
		}

		if(msg$std_msg?$key_id == T)
		{
			std$key_id = msg$std_msg$key_id;
			std$digest = msg$std_msg$digest;
		}
	}

	#
	# Write the log entry.
	#
	if(stdonly == T)
	{
		Log::write(STDLOG, std);
	}
	else
	{
		Log::write(BASELOG, std);
	}

}

#-----------------------------------------------------------------------------
# Routine:	msg_logctl()
#
# Purpose:	This function logs the basic packet values of an NTP
#		control message.
#
#		Log messages are written to the ntp-ctl.log file.
#
#		Called by the ntp_message() event handler.
#
function msg_logctl(c: connection, isorig: bool, msg: NTP::Message, sname: string)
{
	local ctl: ctlinfo;			# NTP control-message info.

	#
	# Return if this call is not an NTP control message.
	#
	if(msg$mode != 6)
	{
		return;
	}

	#
	# Build the control info record.
	#
	ctl =	[
			#
			# Standard fields follow.
			#
			$ts		= network_time(),
			$uid		= c$uid,
			$id		= c$id,

			$version	= msg$version,

			$mode		= msg$mode,
			$modename	= modenames[msg$mode],

			#
			# ControlMessage fields follow.
			#
			$opcode		= 0,

			$respbit	= F,
			$errbit		= F,
			$morebit	= F,

			$sequence	= 0,
			$status		= 0,
			$associd	= 0

			#
			# These fields are optional and are being left unset
			# here.  They might be set from the packet below.
			#
#			$opcodename	= 'unset',
#			$data		= 0,
#			$keyid		= 0,
#			$crypto_cksum	= 0,

		];


	#
	# If we have a control_msg record in the message record, we'll set
	# a bunch of fields in the standard info record.  Some of these
	# fields are required and some are optional.
	#
	# Otherwise, we'll leave the defaults in place.
	#
	if(msg?$control_msg == T)
	{
		#
		# Get the required values from the message.
		#
		ctl$opcode		= msg$control_msg$op_code;
		ctl$opcodename		= getopcodename(ctl$opcode);


		ctl$respbit		= msg$control_msg$resp_bit;
		ctl$errbit		= msg$control_msg$err_bit;
		ctl$morebit		= msg$control_msg$more_bit;

		ctl$sequence		= msg$control_msg$sequence;
		ctl$status		= msg$control_msg$status;
		ctl$associd		= msg$control_msg$association_id;

		#
		# Now we'll pick up the optional values from the message.
		#

		if(msg$control_msg?$data == T)
		{
			ctl$data = msg$control_msg$data;
		}

		if(msg$control_msg?$key_id == T)
		{
			ctl$keyid = msg$control_msg$key_id;
		}

		if(msg$control_msg?$crypto_checksum == T)
		{
			ctl$crypto_cksum = msg$control_msg$crypto_checksum;
		}

	}

	#
	# Write the log entry.
	#
	Log::write(CTLLOG, ctl);

}

#-----------------------------------------------------------------------------
# Routine:	msg_logmode7()
#
# Purpose:	This function logs the basic packet values of an NTP
#		mode-7 message.
#
#		Log messages are written to the ntp-mode7.log file.
#
#		Called by the ntp_message() event handler.
#
function msg_logmode7(c: connection, isorig: bool, msg: NTP::Message, sname: string)

{
	local m7: mode7info;			# NTP mode-7-message info.

	#
	# Return if this call is not an NTP mode-7 message.
	#
	if(msg$mode != 7)
	{
		return;
	}

	#
	# Build the control info record.
	#
	m7 =	[
			#
			# Standard fields follow.
			#
			$ts		= network_time(),
			$uid		= c$uid,
			$id		= c$id,

			$version	= msg$version,

			$mode		= msg$mode,
			$modename	= modenames[msg$mode],

			#
			# Mode-7 message fields follow.
			#
			$reqcode	= 0,
			$authbit	= F,
			$sequence	= 0,
			$impl		= 0,

			$err		= 0,
			$errstr		= ""

			#
			# This field is optional and is being left unset
			# here.  It might be set from the packet below.
			#
#			$data		= 0

		];

	#
	# If we have a mode7_msg record in the message record, we'll set
	# a bunch of fields in the info record.  All of these fields are
	# required except for the data field.
	#
	if(msg?$mode7_msg == T)
	{
		#
		# Get the required values from the message.
		#
		m7$reqcode		= msg$mode7_msg$req_code;
		m7$authbit		= msg$mode7_msg$auth_bit;
		m7$sequence		= msg$mode7_msg$sequence;
		m7$impl			= msg$mode7_msg$implementation;

		m7$err			= msg$mode7_msg$err;
		m7$errstr		= mode7errors[msg$mode7_msg$err];

		#
		# Now we'll pick up the optional values from the message.
		#

		if(msg$mode7_msg?$data == T)
		{
			m7$data = msg$mode7_msg$data;
		}

	}

	#
	# Write the log entry.
	#
	Log::write(MODE7LOG, m7);

}

#-----------------------------------------------------------------------------
# Routine:	msg_logold()
#
# Purpose:	This function logs NTP message values if an old version
#		of NTP is being used.
#
#		Log messages are written to the ntp-oldversions.log file.
#
#		Called by the ntp_message() event handler.
#
function msg_logold(c: connection, isorig: bool, msg: NTP::Message, sname: string)
{
	local strat: count = 0;				# Stratum number.

	#---------------------------------------- testing start
	#
	# Enable testing for old versions.  Messages will randomly be
	# assigned a new NTP version number.
	#
	# If version testing is enabled, the desired test below must
	# be uncommented.
	#
	if(test_oldversion == T)
	{
		#
		# This gives lots of old version numbers.
		#
#		msg$version = rand(4) + 1;

		#
		# This gives many fewer old versions.
		#
		msg$version = rand(100) + 1;
#		print fmt("old ntp version:  %d", msg$version);
		if(msg$version > 3)
		{
			msg$version = 4;
		}
	}

	#---------------------------------------- testing end

	#
	# Return if this packet uses the current version of NTP.
	#
	if(msg$version == CURRENT_NTP_VERSION)
	{
		return;
	}

	#
	# Get the stratum value.
	#
	if((msg?$std_msg == T) && (msg$std_msg?$stratum == T))
	{
		strat = msg$std_msg$stratum;
	}

	#
	# Write a version-log entry iff the packet has an old version.
	#
	Log::write(NTP::VERSLOG, [
			$ts	     = network_time(),
			$uid	     = c$uid,
			$id	     = c$id,

			$version     = msg$version,

			$mode	     = msg$mode,
			$modename    = modenames[msg$mode],

			$stratum     = strat,
			$stratumname = sname

		     ]);

}


#-----------------------------------------------------------------------------
# Routine:	msg_logserver()
#
# Purpose:	This function logs the packet values of an NTP message if
#		this server hasn't been seen yet.
#
#		Log messages are written to the ntp-servers.log file.
#
#		Called by the ntp_message() event handler.
#
function msg_logserver(c: connection, isorig: bool, msg: NTP::Message, sname: string)
{
	local strat: count = 0;				# Stratum number.

	#
	# Write a server-log entry if this is the first time we've seen
	# this NTP server.
	#
	local found = F;		# Address-found flag.
	local recip = c$id$resp_h;	# Shorthand for NTP server addr.
	local ind: count;		# Loop index.

	#
	# Return if this packet isn't from a server.
	#
	if(msg$mode != NTP_MODE_SERVER)
	{
		return;
	}

	#
	# Check the servers list to see if we've already seen this NTP server.
	#
	for(ind in servers)
	{
		if(servers[ind]$haddr == recip)
		{
			found = T;
			break;
		}
	}

	#
	# If we haven't seen this server yet, we'll add it to out list of
	# servers and log the initial sighting.
	# If we have seen it, we'll increment its message count.
	#
	if(found == F)
	{
		#
		# Get the stratum value.
		#
		if((msg?$std_msg == T) && (msg$std_msg?$stratum == T))
		{
			strat = msg$std_msg$stratum;
		}

		#
		# Create a record for this server...
		#
		local srvr: timeserver =
				[
					$ts	   = network_time(),
					$haddr	   = c$id$resp_h,
					$stratum   = strat,
					$responses = 1
				];

		#
		# ... and add it to our list of servers.
		#
		servers += srvr;

		#
		# Write a log entry indicating we've seen this server.
		#
		Log::write(NTP::SERVERLOG,
				[
					$ts	     = srvr$ts,
					$haddr	     = srvr$haddr,

					$stratum     = strat,
					$stratumname = sname,

					$responses   = 1,

					$entrytype   = "initial"

				]);

	}
	else
	{
		#
		# Increment this server's response count.
		#
		servers[ind]$responses += 1;
	}

}

#-----------------------------------------------------------------------------
# Routine:	msg_logkiss()
#
# Purpose:	This function logs the kiss-code (stratum 0) and and ref-id
#		values (stratum 1) from standard NTP messages.
#
#		Log messages are written to the ntp-kisscode.log file.
#
#		Called by the ntp_message() event handler.
#
function msg_logkiss(c: connection, isorig: bool, msg: NTP::Message, sname: string)
{
	local krec: kissinfo;			# Kiss-code NTP info.

	#
	# If this is a control or mode-7 message, then we'll return now.
	#
	if(msg$mode > 5)
	{
		return;
	}

	#
	# Return if we don't have a std_msg record in the message record.
	#
	if(msg?$std_msg == F)
	{
		return;
	}

	#
	# If this message isn't from stratum 0 or 1, return now.
	#
	if(msg$std_msg$stratum > 1)
	{
		return;
	}

	#
	# Build the standard info record.
	#
	krec =	[
			$ts		= network_time(),
			$uid		= c$uid,
			$id		= c$id,

			$mode		= msg$mode,
			$modename	= modenames[msg$mode],

			$stratum	= msg$std_msg$stratum,
			$stratumname	= stratumname(msg$std_msg$stratum)

			#
			# Not setting these optional fields so they'll
			# appear as standard zeek unspecified fields.
			#
#			$kiss_code	= "-",
#			$ref_id		= "-",

		];


	#
	# Set the kiss_code and ref_id optional fields.
	# 
	if(msg$std_msg?$kiss_code == T)
	{
		krec$kiss_code = msg$std_msg$kiss_code;
	}
	if(msg$std_msg?$ref_id == T)
	{
		krec$ref_id = msg$std_msg$ref_id;
	}

	#
	# Set the stratumname according to the stratum number.
	#
#	krec$stratumname = stratumname(msg$std_msg$stratum);


	#
	# Write the log entry.
	#
	Log::write(KISSLOG, krec);

}

#-----------------------------------------------------------------------------
# Routine:	msg_logextensions()
#
# Purpose:	This function logs packet values of an NTP message that
#		has extension fields.
#
#		Log messages are written to the ntp-extensions.log file.
#
#		Called by the ntp_message() event handler.
#
function msg_logextensions(c: connection, isorig: bool, msg: NTP::Message, sname: string)
{
	local strat: count = 0;			# Stratum number.
	local extlen: count;			# Extension's length.
	local fieldtype: count;			# Extension's field type.
	local ftype: string;			# Field type's name.

local excess: string = "88888888";

if(msg$mode > 5)
{
	return;
}

	#
	# Get the stratum value.
	#
	if(msg$std_msg$num_exts == 0)
	{
		return;
	}
	print fmt("logexts:  extension count - %d", msg$std_msg$num_exts);

	if(excess == "")
	{
#		print fmt("excess empty:  sname <%s>   mode - <%s>   excess len - %d", sname, modenames[msg$mode], |excess|);
		return;
	}
	else
	{
#			$modename	= modenames[msg$code],
#		print fmt("excess NOT empty:  sname <%s>   mode - <%s>   excess - <%s>", sname, modenames[msg$code], excess);
	}

	#
	# Get the stratum value.
	#
	if((msg?$std_msg == T) && (msg$std_msg?$stratum == T))
	{
		strat = msg$std_msg$stratum;
	}

	#
	# Get the stratum value.
	#
	if((msg?$std_msg == T) && (msg$std_msg?$num_exts == F))
	{
		print "            logexts IS SETTING NUM_EXTS!!!\n";
		msg$std_msg$stratum = 42;
	}

print fmt("logexts:  numexts - %d      mode - %d      isorig - %d", msg$std_msg$num_exts, msg$mode, isorig);

	#
	# Get the field type of the extension.
	#
#	fieldtype = bytestring_to_count(sub_bytes(excess, 1, 2));

	#
	# Get the length of the extension.
	#
#	extlen = bytestring_to_count(sub_bytes(excess, 3, 2));

	fieldtype = 0;
	extlen = 1;

	#
	# Set the entry type, based on the field type (and maybe length.)
	#
	if(fieldtype == 0)
	{
		#
		# Check explicitly for Crypto-NAK (type 0/len 0.)
		#
		if(extlen == 0)
		{
			ftype = "Crypto-NAK";
		}
		else
		{
			ftype = "unknown";
		}
	}
	else
	{
		if(fieldtype in fieldtype_names)
		{
			ftype = fieldtype_names[fieldtype];
		}
		else
		{
			ftype = fmt("unknown field type %04x", fieldtype);
		}
	}

	print fmt("fieldtype - 0x%04x  %d    extlen    - 0x%04x  %d    %s", fieldtype, fieldtype, extlen, extlen, ftype);

	#
	# Write a log entry for the NTP extension field.
	#
	Log::write(NTP::EXTENSIONLOG,
			[
				$ts	     = network_time(),
				$uid	     = c$uid,
				$id	     = c$id,

				$stratum     = strat,
				$stratumname = sname,

				$num_exts   = msg$std_msg$num_exts,

				$fieldtype   = fieldtype,
				$extlen	     = extlen,

				$entrytype   = ftype

			]);

}

#------------------------------------------------------------------------
#
# Notes on extensions
# 
# internet draft, due to expire on 9/27/19.
# contains info on format of the field type
# 
# says:	'appropriate Field Type Flags, the EF Code, and EF Type values
# 	are defined in an IANA registry'
# haven't found a reference to the actual registry yet
# 
# 
# says:	'Note well that to-date, there are only two defined Extension Field
# 	Types: Autokey, defined by RFC 5906 [RFC5906], and the Experimental
# 	UDP Checksum Complement in the Network Time Protocol, defined by RFC
# 	7821 [RFC7821].'
# 
# has 38 field types defined, mostly for Autokey (RFC5906) and MAC and checksum
# commands.  One for crypto-NAK; this has a field type of 0x0000 and  a field
# length of 0.
# 
# says:	'crypto-NAK, which should be described in RFC 5905.  A crypto-NAK is
# 	used by RFC 5905 as well.  [This is additional evidence that even
# 	though RFC 5906 was Informational, some of its content is REQUIRED for
# 	proper behavior for RFC 5095.]'
# 
# 
# https://datatracker.ietf.org/doc/draft-stenn-ntp-extension-fields/?include_text=1
# 
#------------------------------------------------------------------------

#-----------------------------------------------------------------------------
# Routine:	zeek_init()
#
# Purpose:	Initializes processing of NTP packets.
#
#		Analyzer::register_for_ports() sets up monitoring on
#		the given set of ports.
#
#		These log files are created:
#			- ntp-base.log		comprehensive NTP logging
#
#			- ntp-std.log		NTP logging for messages with
#						modes 1-5
#
#			- ntp-ctl.log		NTP control-message logging
#						(mode 6)
#
#			- ntp-mode7.log		NTP mode-7-message logging
#
#			- ntp-oldversions.log	NTP packets that use old
#						versions of NTP
#
#			- ntp-servers.log	NTP servers whose traffic has
#						been observed
#
#		The initialization code was modelled on the bro DNS module.
#
event zeek_init()
{
	print "zeek_init:  registering NTP port";

	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);

	Log::create_stream(BASELOG, [$columns = stdinfo, $path = "ntp-base"]);

	Log::create_stream(STDLOG, [$columns = stdinfo, $path = "ntp-std"]);

	Log::create_stream(CTLLOG, [$columns = ctlinfo, $path = "ntp-ctl"]);

	Log::create_stream(MODE7LOG, [$columns = mode7info, $path = "ntp-mode7"]);

	Log::create_stream(VERSLOG,[$columns = versinfo, $path = "ntp-oldversions"]);

	Log::create_stream(SERVERLOG,[$columns = timeserver, $path = "ntp-servers"]);

	Log::create_stream(KISSLOG,[$columns = kissinfo, $path = "ntp-kisscode"]);

#	Log::create_stream(EXTENSIONLOG,[$columns = extinfo, $path = "ntp-extensions"]);

	print "zeek_init:  NTP port registered";

	if(test_oldversion == T)
	{
		print " ";
		print "turning ON testing of old versions of NTP";
		print " ";
	}


#	print "zeek_init:  done";
}

#-----------------------------------------------------------------------------
# Routine:	ntp_message()
#
# Purpose:	Event handler for the ntp_message event.  When an NTP packet is
#		encountered, the packet's data are logged to the NTP log file.
#
#		In this prototype plugin, all the standard NTP fields are
#		logged.
#
#		The following actions are performed by this event handler:
#
#			- log the values of all NTP messages
#			  (ntp-base.log)
#
#			- log the values of all NTP control messages
#			  (ntp-ctl.log)
#
#			- log the values of all NTP mode-7 messages
#			  (ntp-mode7.log)
#
#			- log the values of all other NTP messages
#			  (ntp-std.log)
#
#			- log messages that have a non-current version of NTP
#			  (ntp-oldversions.log)
#
#			- log messages from previously unseen NTP servers
#			  (ntp-servers.log)
#
#			- log kiss-code/ref-id values from stratum 0 and 1
#			  NTP messages
#			  (ntp-kisscode.log)
#
#

event ntp_message(c: connection, isorig: bool, msg: NTP::Message)
{
	local sname: string;			# Translated stratum name.

	#
	# Get the text name of the message's stratum.
	#
	sname = "<unknown stratum name>";
	if(msg?$std_msg == T)
	{
		sname = stratumname(msg$std_msg$stratum);
	}

	#
	# Log the basic values of the NTP packet -- all NTP messages will
	# be logged.
	#
	msg_logstd(c, isorig, msg, sname, F);

	#
	# Log the values of the NTP packets, depending on the message's mode.
	#
	if(msg$mode == 6)
	{
		msg_logctl(c, isorig, msg, sname);
	}
	else if(msg$mode == 7)
	{
		msg_logmode7(c, isorig, msg, sname);
	}
	else if(msg$mode < 6)
	{
		msg_logstd(c, isorig, msg, sname, T);
	}

	#
	# Log values of the NTP packet if it has an old version number.
	#
	msg_logold(c, isorig, msg, sname);

	#
	# Log values of the NTP packet if this is a previously unseen
	# NTP server.
	#
	msg_logserver(c, isorig, msg, sname);

	#
	# Log kiss-code and ref-id values from stratum 0 and 1 NTP messages.
	#
	msg_logkiss(c, isorig, msg, sname);

	#
	# Log values of the NTP packet if the packet has extension fields.
	#
#	msg_logextensions(c, isorig, msg, sname);

}

#-----------------------------------------------------------------------------
# Routine:	zeek_done()
#
# Purpose:	Finalizes processing of NTP packets.
#
#		A final count of each server's responses is written to the
#		NTP server log.  These entries have an entrytype of "final".
#
#
event zeek_done()
{

	print "zeek_done:  closing up";

	#
	# Log the summaries of server usage.
	#
	for(ind in servers)
	{

#		print fmt("%2d:  %-15s    %d     %d", ind, servers[ind]$haddr, servers[ind]$stratum, servers[ind]$responses);

		local srvr = servers[ind];	# Server record.
		local sname: string;		# Server's stratum name.

		#
		# Get the text name of the message's stratum.
		#
		sname = stratumname(srvr$stratum);

		#
		# Write a log entry indicating we've seen this server.
		#
		Log::write(NTP::SERVERLOG,
				[
					$ts	     = network_time(),
					$haddr	     = srvr$haddr,

					$stratum     = srvr$stratum,
					$stratumname = sname,

					$responses   = srvr$responses,

					$entrytype   = "final"
				]);

	}

}

