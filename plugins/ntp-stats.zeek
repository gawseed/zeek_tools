##!	ntp-scripts.zeek	Gathers statistics on NTP traffic.
#
#	This plugin gathers statistics on NTP traffic.  It is used in
#	conjunction with zeek to analyze NTP traffic, and then generates
#	statistics on the traffic.  Some results are logged as normal for
#	zeek logging.  However, other results don't fit that model well
#	and are instead written to standard output.
#
#	This functionality was originally added to ntp.zeek.  It was split
#	off after ntp.zeek v1.6 and moved to ntp-scripts.zeek.
#
#	This script requires zeek 3.0.0 or later.
#
#	The following statistics are gathered for NTP traffic:
#
#		- count of incoming packets				(v1.0)
#		- count of outgoing packets				(v1.0)
#
#		- count of outgoing packets, based on NTP mode		(v1.1)
#		- count of incoming packets, based on NTP mode		(v1.1)
#
#		- count of incoming destination addresses		(v1.2)
#		- count of outgoing destination addresses		(v1.2)
#		- count of reference ids seen				(v1.2)
#		- count of reference addresses seen			(v1.2)
#		- count of kiss codes seen				(v1.2)
#		- count of reference-ids in mode3			(v1.2)
#		- count of reference-ids in mode4			(v1.2)
#		- count of incoming kiss-codes				(v1.2)
#		- count of outgoing kiss-codes				(v1.2)
#		- reference-timestamps					(v1.2)
#
#	Results are written to the ntp-stats.log.
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
#		1.0	Initial revision.				191230
#			This is actually ntp.zeek version 1.6.
#		1.1	Functionality inherent to ntp.zeek was removed.	191231
#		1.2	Many additional statistics were added.		200106
#			New method of determining incoming/outgoing.
#		1.3	Changed to use zeek logging to write the	200121
#			ntp-stats.log.
#			(zeek doesn't let you output tabs otherwise.)
#
#
#	This script was written for the GAWSEED project.
#


@load base/frameworks/notice

@load base/protocols/conn

@load base/protocols/conn/main

module NTP;


#
# Version information.
#
const NAME    = "ntp-stats.zeek";
const VERSION = fmt("%s version: 1.3", NAME);

#
# Local subnet.  This is used in outgoing().
#
const LOCALNET = 192.168.1.1/24;


export
{
	#   
	# Define the log file we'll be using.
	#
	redef enum Log::ID += { STATLOG};

	#
	# Data recorded for NTP statistics we gather.
	#
	type statinfo: record
	{
		statgroup:	string		&log;
		in_out:		string		&log &optional;
		field:		string		&log;
		value:		count		&log;
	};


	#------------------------------------------------------------
	#
	# Constants used in NTP packets.
	#

	const CURRENT_NTP_VERSION = 4;			# Current NTP version.

	#
	# Mode values for NTP packets.
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
	# Statistics values used by msg_stats().
	#
	global incoming_cnt: count;	# Count of incoming NTP packets.
	global outgoing_cnt: count;	# Count of outgoing NTP packets.

	global incoming_modes: vector of count;	# Cnt of incoming pkts by mode. 
	global outgoing_modes: vector of count;	# Cnt of outgoing pkts by mode. 

	global destaddrs_loc: table[addr] of count;	# Count of local
							# destination addresses.
	global destaddrs_rmt: table[addr] of count;	# Count of remote
							# destination addresses.

	#------------------------------------------------------------
	# Data for simple statistics.
	#

	#
	# Counts of incoming, outgoing, and all kiss-code packets.
	#
	global kisscodes: table[string] of count;
	global kisscodes_in: table[string] of count;
	global kisscodes_out: table[string] of count;

	#
	# Counts of reference ids, addresses, and times.
	#
	global refids:	  table[string] of count;
	global refaddrs:  table[addr] of count;
	global reftstmps: table[time] of count;

	global refid_mode3:  table[string] of count;
	global refid_mode4:  table[string] of count;

	#------------------------------------------------------------
	# Data for packet comparisons and matching packets.
	#

	# Count of NTP versions seen.
	global version_counts:  vector of int;

	#
	global match_mode12:  table[addr] of int;
	global match_mode12_addrs:  table[addr] of count;

	global match_mode34:  table[addr] of int;
	global match_mode34_addrs:  table[addr] of count;

	# Incoming NTP packet counts by day.
	global in_hour_bins: table[string] of int;

	# Incoming NTP packet counts by day.
	global in_day_bins: table[string] of int;

	# Count of outgoing NTP pkts binned per day per destination address.
	global out_day_resp_bins: table[string] of table[addr] of int;

	# Count of outgoing NTP pkts binned per hour per destination address.
	global out_hour_resp_bins: table[string] of table[addr] of int;

	# Count of outgoing NTP pkts binned per day per internal address.
	global out_day_orig_bins: table[string] of table[addr] of int;

	# Count of outgoing NTP pkts binned per day per internal address.
	global out_hour_orig_bins: table[string] of table[addr] of int;

	# Incoming NTP packet counts by day and by address.
	global in_day_src_bins: table[string] of table[addr] of int;

	# Incoming NTP packet counts by hour and by address.
	global in_hour_src_bins: table[string] of table[addr] of int;

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
# Routine:	initstats()
#
# Purpose:	Initialize statistics fields used by msg_stats().
#
function initstats()
{
	#
	# Basic counts of incoming/outgoing packets.
	#
	incoming_cnt = 0;
	outgoing_cnt = 0;

	#
	# Counts of incoming/outgoing packets, by mode.
	#
	for(mode in modelist)
	{
		incoming_modes[mode] = 0;
		outgoing_modes[mode] = 0;
	}

	#
	# Counts of each version value.
	#
	for(ind in vector(0, 1, 2, 3, 4, 5, 6, 7, 8))
	{
		version_counts += 0;
	}
}

#-----------------------------------------------------------------------------
# Routine:	outgoing()
#
# Purpose:	Determine if a message is outgoing or incoming.
#
#		zeek doesn't really look at traffic as being outgoing or
#		incoming.  Instead, it designates each packet as being from
#		either the originating host or the responding host.
#
#		If this packet was sent by the originator, we'll check if the
#		originator's address is in our local subnet.  If so, this is
#		an outgoing packet; if not, it's an incoming packet.
#
#		"our local network" is defined above in the LOCALNET constant.
#
function outgoing(c: connection, isorig: bool, msg: NTP::Message): bool
{
	local senderhost = 127.0.0.1;			# Sending host.

#	print fmt("orighost:  %s        %s", orighost, orignet);

	#
	# If this packet was sent by the originator, we'll check against
	# the originator's address.
	# If this packet was sent by the responder, we'll check against
	# the responder's address.
	#
	if(isorig == T)
	{
		senderhost = c$id$orig_h;
	}
	else
	{
		senderhost = c$id$resp_h;
	}

	local sendernet = senderhost/24;		# Sending host's subnet.

	#
	# Return true/false depending on if the sender's subnet is our subnet.
	#
	if(sendernet != LOCALNET)
	{
		return(F);
	}

	return(T);


	#------------------------------------------------------------
	# Old method below; retained for reference, not for use.
	#

	#
	# If originating host's network doesn't match our local network,
	# this is assumed to be an incoming packet.
	#
	local orighost = c$id$orig_h;
	local orignet = orighost/24;

	if(orignet != LOCALNET)
	{
		return(F);
	}

	#
	# The originating host's network matches our local network, so
	# this is assumed to be an outgoing packet.
	#
	return(T);

}

#-----------------------------------------------------------------------------
# Routine:	msg_stats()
#
# Purpose:	This function gathers a set of statistics on NTP packets.
#		They are not logged here, but on exit in zeek_done().
#
#		Log messages will be written to the ntp-stats.log file.
#
#		Called by the ntp_message() event handler.
#
function msg_stats(c: connection, isorig: bool, msg: NTP::Message, sname: string)
{
	local outgoingpkt: bool;		# Flag for outgoing packet.

	local mode: count;			# NTP message's mode.
	local vers: count;			# NTP message's version.
	local origaddr: addr;			# NTP msg's originator address.
	local respaddr: addr;			# NTP msg's responder address.

	local hourind: string;			# Time bin hour index.
	local dayind: string;			# Time bin day index.

	local ntime = network_time();		# Packet time copy.

	#
	# Get the day index and hour index for our time bins.
	#
	hourind = strftime("%Y%m%d-%H", ntime);
	dayind  = strftime("%Y%m%d", ntime);

#	print "msg_stats:  down in";

	#
	# Determine if this is an outgoing or incoming packet.
	#
	outgoingpkt = outgoing(c, isorig, msg);

	#
	# Get some shorthand fields.
	#
	mode = msg$mode;
	vers = msg$version;
	origaddr = c$id$orig_h;
	respaddr = c$id$resp_h;

	if(c?$conn == T)
	{
		local locorig = c$conn$local_orig;
		local rmtorig = c$conn$local_resp;
		print fmt("locorig - %d    rmtorig - %d", locorig, rmtorig);
	}
#	else
#	{
#		print "no conn!";
#		print fmt("woof c:  %s", c);
#	}

	#
	# Bump the NTP version count.  The in-packet version field is a
	# three-bit value, which means the version *should* only be from
	# 0 to 7.  Anything higher than 7 will be lumped into one count.
	#
	if(vers < 8)
	{
		++version_counts[vers];
	}
	else
	{
		++version_counts[8];
	}
		

	#
	# Handle statistics for based on if the packet is incoming or outgoing.
	#
	if(outgoingpkt == T)
	{
#		print fmt("outgoing %-16s   %s", origaddr, respaddr);

		#
		# Simple outgoing count.
		#
		outgoing_cnt += 1;

		#
		# Outgoing count by mode.
		#
		outgoing_modes[mode] += 1;

		#
		# Count of outgoing remote addresses.
		#
		destaddrs_rmt[respaddr] =
			(respaddr in destaddrs_rmt) ? (destaddrs_rmt[respaddr] + 1) : 1;

		#
		# Count matched and unmatched client/server messages.
		# Where the server is outside our enclave.
		# This is the client message.
		#
		if(mode == NTP_MODE_CLIENT)
		{
			if(respaddr ! in match_mode34)
			{
				match_mode34[respaddr] = 0;
				match_mode34_addrs[respaddr] = 0;
			}

			match_mode34[respaddr] -= 1;
			match_mode34_addrs[respaddr] += 1;

#			print fmt("           subbing match for %s              %s", respaddr, c$uid);
		}

		#------------------------------
		# Outgoing NTP packet counts by day and responder address.
		#
		if(dayind !in out_day_resp_bins)
		{
			out_day_resp_bins[dayind] = table();
		}
		if(respaddr !in out_day_resp_bins[dayind])
		{
			out_day_resp_bins[dayind][respaddr] = 0;
		}

		++out_day_resp_bins[dayind][respaddr];

		#------------------------------
		# Outgoing NTP packet counts by hour and responder address.
		#
		if(hourind !in out_hour_resp_bins)
		{
			out_hour_resp_bins[hourind] = table();
		}
		if(respaddr !in out_hour_resp_bins[hourind])
		{
			out_hour_resp_bins[hourind][respaddr] = 0;
		}

		++out_hour_resp_bins[hourind][respaddr];

		#------------------------------
		# Outgoing NTP packet counts by day and originator address.
		#
		if(dayind !in out_day_orig_bins)
		{
			out_day_orig_bins[dayind] = table();
		}
		if(origaddr !in out_day_orig_bins[dayind])
		{
			out_day_orig_bins[dayind][origaddr] = 0;
		}

		++out_day_orig_bins[dayind][origaddr];

		#------------------------------
		# Outgoing NTP packet counts by hour and originator address.
		#
		if(hourind !in out_hour_orig_bins)
		{
			out_hour_orig_bins[hourind] = table();
		}
		if(origaddr !in out_hour_orig_bins[hourind])
		{
			out_hour_orig_bins[hourind][origaddr] = 0;
		}

		++out_hour_orig_bins[hourind][origaddr];

	}
	else				# incoming packets
	{
#		print fmt("incoming %-16s   %s", origaddr, respaddr);

		#
		# Simple incoming count.
		#
		incoming_cnt += 1;

		#
		# Incoming count by mode.
		#
		incoming_modes[mode] += 1;

		#
		# Count of incoming remote addresses.
		#
		destaddrs_loc[origaddr] =
			(origaddr in destaddrs_loc) ? (destaddrs_loc[origaddr] + 1) : 1;

		#
		# Count matched and unmatched client/server messages.
		# Where the server is outside our enclave.
		# This is the server message.
		#
		if(mode == NTP_MODE_SERVER)
		{
			if(respaddr ! in match_mode34)
			{
				match_mode34[respaddr] = 0;
				match_mode34_addrs[respaddr] = 0;
			}

			match_mode34[respaddr] += 1;
			match_mode34_addrs[respaddr] += 1;

	#		print fmt("           adding match for %s              %s", respaddr, c$uid);
		}

		#------------------------------
		# Incoming NTP packet counts by hour.
		#
		if(hourind ! in in_hour_bins)
		{
			in_hour_bins[hourind] = 0;
		}
		++in_hour_bins[hourind];

		#------------------------------
		# Incoming NTP packet counts by day.
		#
		if(dayind ! in in_day_bins)
		{
			in_day_bins[dayind] = 0;
		}
		++in_day_bins[dayind];

		#------------------------------
		# Incoming NTP packet counts by day and by address.
		#
		if(dayind !in in_day_src_bins)
		{
			in_day_src_bins[dayind] = table();
		}
		if(origaddr !in in_day_src_bins[dayind])
		{
			in_day_src_bins[dayind][origaddr] = 0;
		}
		++in_day_src_bins[dayind][origaddr];

		#------------------------------
		# Incoming NTP packet counts by hour in day and by address.
		#
		if(hourind !in in_hour_src_bins)
		{
			in_hour_src_bins[hourind] = table();
		}
		if(origaddr !in in_hour_src_bins[hourind])
		{
			in_hour_src_bins[hourind][origaddr] = 0;
		}

		++in_hour_src_bins[hourind][origaddr];

	}

	if(msg?$std_msg == T)
	{
		#
		# Save the count of each unique reference id, reference
		# address, and kiss code.
		#
		if(msg$std_msg?$ref_id == T)
		{
			local ri = msg$std_msg$ref_id;
			refids[ri] = (ri in refids) ? (refids[ri] + 1) : 1;

			if(mode == NTP_MODE_CLIENT)
			{
				if(ri == "INIT")
				{
					refid_mode3["INIT"] = ("INIT" in refid_mode3) ? (refid_mode3["INIT"] + 1) : 1;
				}
				else if(ri == "STEP")
				{
					refid_mode3["STEP"] = ("STEP" in refid_mode3) ? (refid_mode3["STEP"] + 1) : 1;
				}
				else if(ri == "SYNC")
				{
					refid_mode3["SYNC"] = ("SYNC" in refid_mode3) ? (refid_mode3["SYNC"] + 1) : 1;
				}
			}

			if(mode == NTP_MODE_SERVER)
			{
				if(ri == "INIT")
				{
					refid_mode4["INIT"] = ("INIT" in refid_mode4) ? (refid_mode4["INIT"] + 1) : 1;
				}
				else if(ri == "STEP")
				{
					refid_mode4["STEP"] = ("STEP" in refid_mode4) ? (refid_mode4["STEP"] + 1) : 1;
				}
				else if(ri == "SYNC")
				{
					refid_mode4["SYNC"] = ("SYNC" in refid_mode4) ? (refid_mode4["SYNC"] + 1) : 1;
				}
			}

		}
		if(msg$std_msg?$ref_addr == T)
		{
			local ra = msg$std_msg$ref_addr;
			refaddrs[ra] = (ra in refaddrs) ? (refaddrs[ra] + 1) : 1;
		}
		if(msg$std_msg?$kiss_code == T)
		{
			local kc = msg$std_msg$kiss_code;
			kisscodes[kc] = (kc in kisscodes) ? (kisscodes[kc] + 1) : 1;

			if(outgoingpkt)
			{
				kisscodes_out[kc] = (kc in kisscodes_out) ? (kisscodes_out[kc] + 1) : 1;
			}
			else
			{
				kisscodes_in[kc] = (kc in kisscodes_in) ? (kisscodes_in[kc] + 1) : 1;
			}
		}

		#
		# Save the count of each unique reference timestamp.
		#
		local rt = msg$std_msg$ref_time;
		reftstmps[rt] = (rt in reftstmps) ? (reftstmps[rt] + 1) : 1;



		local origmask = origaddr/24;	# Subnet of originator address.

		if((mode == NTP_MODE_CLIENT) && (origmask == LOCALNET))
		{

		}

	}

}

#-----------------------------------------------------------------------------
# Routine:	logstat()
#
# Purpose:	This function writes the given statistic to our log file.
#		We are using this since zeek prevents us from writing tabs
#		to a log file any other way.
#
#		Log messages are written to the ntp-stats.log file.
#
#		Called by the zeek_done() event handler.
#
function logstat(stgrp: string, direction: string, datafield: string, cnt: count)
{
	local statrec: statinfo;			# NTP statistics info.

	statrec = [
			$statgroup	= stgrp,
			$field		= datafield,
			$value		= cnt
		  ];

	#
	# Only include a direction if one was specified.
	#
	if(direction != "")
	{
		statrec$in_out = direction;
	}

	Log::write(STATLOG, statrec);

}

#-----------------------------------------------------------------------------
# Routine:	sortstr()
#
# Purpose:	Comparison function for sorting strings.
#
#
function sortstr(str1: string, str2: string): int
{

	if(str1 < str2)
	{
		return(-1);
	}
	else if(str1 > str2)
	{
		return(1);
	}
	else
	{
		return(0);
	}

}

#-----------------------------------------------------------------------------
# Routine:	sortaddr()
#
# Purpose:	Comparison function for sorting addresses.
#
#		There are three potential sorting methods given below:
#		ASCII sort, numerical sort, and a hybrid sort.
#
#		sortaddr() uses sortstr(), so it *must* follow its definition.
#
#
function sortaddr(addr1: addr, addr2: addr): int
{

	#
	# This is the ASCII sorting method.  It gives this list:
	#	206.1.1.1
	#	208.1.1.1
	#	23.1.1.1
	#	66.1.1.1
	#
	if(F)
	{
		local str1 = fmt("%s", addr1);
		local str2 = fmt("%s", addr2);

		return(sortstr(str1, str2));
	}

	#
	# This is the numerical sorting method.  It gives this list:
	#	23.1.1.1
	#	66.1.1.1
	#	206.1.1.1
	#	208.1.1.1
	#
	if(T)
	{
		if(addr1 < addr2)
		{
			return(-1);
		}
		else if(addr1 > addr2)
		{
			return(1);
		}
		else
		{
			return(0);
		}
	}

	#
	# This is the hybird sorting method.  It gives this list:
	#	23.1.1.1
	#	206.1.1.1
	#	208.1.1.1
	#	66.1.1.1
	#
	#			hybrid sorting is not yet implemented!
	#

}

#-----------------------------------------------------------------------------
# Routine:	sortkeys_ta()
#
# Purpose:	Return a sorted list of a table's keys.
#		The table is a table of ints, indexed by addrs.
#
function sortkeys_ta(tabint: table[addr] of int): vector of addr
{
	local keyvec: vector of addr;		# Keys for table.

	#
	# Ensure the key vector is empty.
	#
	resize(keyvec, 0);

	#
	# Build the key vector...
	#
	for (dsbk in tabint)
	{
		keyvec += dsbk;
	}

	#
	# ... and sort it.
	#
	sort(keyvec, sortaddr);

	return(keyvec);
}

#-----------------------------------------------------------------------------
# Routine:	sortkeys_ti()
#
# Purpose:	Return a sorted list of a table's keys.
#		The table is a table of ints.
#
#		It'd be really nice if we didn't have to have this
#		as well as sortkeys_tti().
#
function sortkeys_ti(tabint: table[string] of int): vector of string
{
	local keyvec: vector of string;		# Keys for table.

	#
	# Ensure the key vector is empty.
	#
	resize(keyvec, 0);

	#
	# Build the key vector...
	#
	for (dsbk in tabint)
	{
		keyvec += dsbk;
	}

	#
	# ... and sort it.
	#
	sort(keyvec, sortstr);

	return(keyvec);
}

#-----------------------------------------------------------------------------
# Routine:	sortkeys_tti()
#
# Purpose:	Return a sorted list of a table's keys.
#		The table is a table of tables of ints.
#
#		It'd be really nice if we didn't have to have this
#		as well as sortkeys_ti().
#
function sortkeys_tti(tabtabint: table[string] of table[addr] of int): vector of string
{
	local keyvec: vector of string;		# Keys for table.

	#
	# Ensure the key vector is empty.
	#
	resize(keyvec, 0);

	#
	# Build the key vector...
	#
	for (dsbk in tabtabint)
	{
		keyvec += dsbk;
	}

	#
	# ... and sort it.
	#
	sort(keyvec, sortstr);

	return(keyvec);
}

#-----------------------------------------------------------------------------
# Routine:	simple_stats()
#
# Purpose:	Calculate the "simple" statistics.
#
#
function simple_stats()
{
	local addrstr: string;				# Address string.

	print "        logging simple statistics";


	#
	# Packet counts.
	#
	logstat("count-simple", "incoming", "packets", incoming_cnt);
	logstat("count-simple", "outgoing", "packets", outgoing_cnt);

	#
	# Packet counts for incoming packets, based on NTP mode.
	#
	for(mode in modelist)
	{
		logstat("count-mode", "incoming", modenames[mode], incoming_modes[mode]);
	}

	#
	# Packet counts for outgoing packets, based on NTP mode.
	#
	for(mode in modelist)
	{
		logstat("count-mode", "outgoing", modenames[mode], outgoing_modes[mode]);
	}

	#
	# Packet counts for local destination addresses.
	#
	for(saddr in destaddrs_loc)
	{
		addrstr = fmt("%s", saddr);
		logstat("destination-addresses", "incoming", addrstr, destaddrs_loc[saddr]);
	}

	#
	# Packet counts for remote destination addresses.
	#
	for(daddr in destaddrs_rmt)
	{
		addrstr = fmt("%s", daddr);
		logstat("destination-addresses", "outgoing", addrstr, destaddrs_rmt[daddr]);
	}

	#
	# Reference-id counts.
	#
	for(rid in refids)
	{
		logstat("reference-id", "", rid, refids[rid]);
	}

	#
	# Reference-id counts.
	#
	for(rad in refaddrs)
	{
		addrstr = fmt("%s", rad);
		logstat("reference-addr", "", addrstr, refaddrs[rad]);
	}

	#
	# Reference-id counts for mode 3.
	#
	if(|refid_mode3| > 0)
	{
		for(rid3 in refid_mode3)
		{
			logstat("reference-id-mode3", "", rid3, refid_mode3[rid3]);
		}
	}
	else
	{
		logstat("reference-id-mode3", "", "(none)", 0);
	}

	#
	# Reference-id counts for mode 4.
	#
	if(|refid_mode4| > 0)
	{
		for(rid4 in refid_mode4)
		{
			logstat("reference-id-mode4", "", rid4, refid_mode4[rid4]);
		}
	}
	else
	{
		logstat("reference-id-mode4", "", "(none)", 0);
	}

	#
	# All kiss-code counts.
	#
	for(kid in kisscodes)
	{
		logstat("kiss-codes", "", kid, kisscodes[kid]);
	}

	#
	# Incoming kiss-code counts.
	#
	for(kid in kisscodes_in)
	{
		logstat("kiss-codes", "incoming", kid, kisscodes_in[kid]);
	}
	if(|kisscodes_in| == 0)
	{
		logstat("kiss-codes", "incoming", "(none)", 0);
	}

	#
	# Outgoing kiss-code counts.
	#
	for(kid in kisscodes_out)
	{
		logstat("kiss-codes", "outgoing", kid, kisscodes_out[kid]);
	}
	if(|kisscodes_out| == 0)
	{
		logstat("kiss-codes", "outgoing", "(none)", 0);
	}

	#
	# Reference-timestamp counts.
	#
	for(rtid in reftstmps)
	{
		addrstr = fmt("%s", rtid);
		logstat("reference-timestamps", "", addrstr, reftstmps[rtid]);
	}

}


#-----------------------------------------------------------------------------
# Routine:	zeek_init()
#
# Purpose:	Initializes processing of NTP packets.
#
#		Analyzer::register_for_ports() sets up monitoring on
#		the given set of ports.
#
event zeek_init()
{
	print "zeek_init:  registering NTP port";

	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);

	Log::create_stream(STATLOG,[$columns = statinfo, $path = "ntp-stats"]);


	print "zeek_init:  NTP port registered";

	#
	# Initialize data for statistics gathering.
	#
	initstats();

#	print "zeek_init:  done";

}

#-----------------------------------------------------------------------------
# Routine:	ntp_message()
#
# Purpose:	Event handler for the ntp_message event.  When an NTP packet
#		is encountered, statistics about the packet are gathered.
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
	# Gather statistics on this packet.
	#
	msg_stats(c, isorig, msg, sname);

}

#-----------------------------------------------------------------------------
# Routine:	zeek_done()
#
# Purpose:	Finalizes processing of NTP packets.
#
#		A bunch of NTP-related statistic are generated and written
#		to the ntp-stats.log.
#
event zeek_done()
{
	local keys: vector of string;		# Keys for table, to be sorted.
	local dsbk: string;			# Key to server bins.
	local sbk: addr;			# Key to server bins' tables.
	local addrbuf: string;			# Space-buffered address string.

	local subkeyaddr: addr;			# Table subkey for addr index.
	local subkeyind: int;			# Table subkey for int index.

	local databins: table[addr] of int;
	local subkeyaddrs: vector of addr;

	print "";
	print "zeek_done:  closing up";

	simple_stats();


	#-------------------------------------------------------------

	local hbk: string;
	local dbk: string;

print "";
print "look at the match_mode34 and match_mode34_addrs stats to ensure they're okay";
print "";
print "calculate percentages for version counts at end";
print "";
print "have all loops here use databins, rather than other locals";
print "";
print "";

if(T)
{
	print "---------------------------------------------------";
	print "match_mode34_addrs:";
	for(za in match_mode34_addrs)
	{
		addrbuf = fmt("%s                         ", za);
		print fmt("    %s        %d", addrbuf[0:20], match_mode34_addrs[za]);
	}
	print "";

	#-------------------------------------------------------------

	print "---------------------------------------------------";
	print "match_mode34:";
	for(zb in match_mode34)
	{
		addrbuf = fmt("%s                         ", zb);
		print fmt("    %s        %d", addrbuf[0:20], match_mode34[zb]);
	}
	print "";
}

	#-------------------------------------------------------------
	#
	# Print the daily counts of incoming NTP packets.
	#

	keys = sortkeys_ti(in_day_bins);

	print "---------------------------------------------------";
	print "NTP packet counts -- incoming, daily, overall totals:";
	for (keyind in keys)
	{
		dsbk = keys[keyind];

		addrbuf = fmt("%s                         ", dsbk);
		print fmt("        %s        %s        ", addrbuf[0:20], in_day_bins[dsbk]);
	}
	print "";

	#-------------------------------------------------------------
	#
	# Print the hourly counts of incoming NTP packets.
	#

	keys = sortkeys_ti(in_hour_bins);

	print "---------------------------------------------------";
	print "NTP packet counts -- incoming, hourly, overall totals:";
	for (keyind in keys)
	{
		dsbk = keys[keyind];

		addrbuf = fmt("%s                         ", dsbk);
		print fmt("        %s        %s        ", addrbuf[0:20], in_hour_bins[dsbk]);
	}
	print "";

	#-------------------------------------------------------------
	#
	# Print the counts of outgoing NTP packet, based on days.
	#

	keys = sortkeys_tti(out_day_resp_bins);

	print "---------------------------------------------------";
	print "NTP packet counts -- outgoing, daily, by destination:";
	for (keyind in keys)
	{
		dsbk = keys[keyind];
		local servdaycnts = out_day_resp_bins[dsbk];

		print fmt("  %s", dsbk);

		for (sbk in servdaycnts)
		{
			addrbuf = fmt("%s                         ", sbk);
			print fmt("        %s    %s", addrbuf[0:20], servdaycnts[sbk]);
		}
	}
	print "";

	#-------------------------------------------------------------
	#
	# Print the counts of outgoing NTP packet, based on hours.
	#

	keys = sortkeys_tti(out_hour_resp_bins);

	print "---------------------------------------------------";
	print "NTP packet counts -- outgoing, hourly, by destination:";
	for (keyind in keys)
	{
		dsbk = keys[keyind];
		databins = out_hour_resp_bins[dsbk];

		subkeyaddrs = sortkeys_ta(databins);

		print fmt("  %s", dsbk);

		for (subkeyind in subkeyaddrs)
		{
			subkeyaddr = subkeyaddrs[subkeyind];

			addrbuf = fmt("%s                         ", subkeyaddr);
			print fmt("        %s    %s", addrbuf[0:20], databins[subkeyaddr]);
		}

	}
	print "";

	#-------------------------------------------------------------
	#
	# Print the counts of NTP client usage, based on days.
	#

	keys = sortkeys_tti(out_day_orig_bins);

	print "---------------------------------------------------";
	print "NTP packet counts -- daily, by client:";
	for (keyind in keys)
	{
		dsbk = keys[keyind];
		databins = out_day_orig_bins[dsbk];

		subkeyaddrs = sortkeys_ta(databins);

		print fmt("  %s", dsbk);

		for (subkeyind in subkeyaddrs)
		{
			subkeyaddr = subkeyaddrs[subkeyind];
#		for (sbk in databins)
#		{
			addrbuf = fmt("%s                         ", subkeyaddr);
			print fmt("        %s    %s", addrbuf[0:20], databins[subkeyaddr]);
		}
	}
	print "";


	#-------------------------------------------------------------
	#
	# Print the counts of NTP client usage, based on hours.
	#

	keys = sortkeys_tti(out_hour_orig_bins);

	print "---------------------------------------------------";
	print "NTP packet counts -- hourly, by client:";
	for (keyind in keys)
	{
		dsbk = keys[keyind];
		databins = out_hour_orig_bins[dsbk];

		subkeyaddrs = sortkeys_ta(databins);

		print fmt("  %s", dsbk);

		for (subkeyind in subkeyaddrs)
		{
			addrbuf = fmt("%s                         ", subkeyaddr);
			print fmt("        %s    %s", addrbuf[0:20], databins[subkeyaddr]);
		}
	}
	print "";

	#-------------------------------------------------------------
	#
	# Print the counts of incoming NTP packets, based on source and day.
	#

	keys = sortkeys_tti(in_day_src_bins);

	print "---------------------------------------------------";
	print "NTP packet counts -- incoming, daily by source:";
	for (keyind in keys)
	{
		dsbk = keys[keyind];
		databins = in_day_src_bins[dsbk];

		subkeyaddrs = sortkeys_ta(databins);

		print fmt("  %s", dsbk);

		for (subkeyind in subkeyaddrs)
		{
			subkeyaddr = subkeyaddrs[subkeyind];

			addrbuf = fmt("%s                         ", subkeyaddr);
			print fmt("        %s    %s        ", addrbuf[0:20], databins[subkeyaddr]);
		}
	}
	print "";

	#-------------------------------------------------------------
	#
	# Print the counts of incoming NTP packets, based on source and hour.
	#

	keys = sortkeys_tti(in_hour_src_bins);

	print "---------------------------------------------------";
	print "NTP packet counts -- incoming, hourly by source:";
	for (keyind in keys)
	{
		dsbk = keys[keyind];
		databins = in_hour_src_bins[dsbk];

		subkeyaddrs = sortkeys_ta(databins);

		print fmt("  %s", dsbk);

		for (subkeyind in subkeyaddrs)
		{
			subkeyaddr = subkeyaddrs[subkeyind];

			addrbuf = fmt("%s                         ", subkeyaddr);
			print fmt("        %s    %s", addrbuf[0:20], databins[subkeyaddr]);
		}
	}
	print "";

	#-------------------------------------------------------------
	#
	# Print the counts of NTP versions seen.
	#

	print "---------------------------------------------------";
	print "NTP versions:";
	for (ind in version_counts)
	{
		addrbuf = fmt("%s                         ", sbk);
		if(ind < 8)
		{
			print fmt("        version %d - %d", ind, version_counts[ind]);
		}
		else
		{
			print "";
			print fmt("        impossible versions - %d", version_counts[ind]);
		}
	}
	print "";

}


#
# Todo:
#
#
