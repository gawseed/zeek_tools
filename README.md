
# Zeek-Related Tools / Plugins

This repository has software written to support the Zeek network
analyzer. Several protocol-specific plugins were written, as well as a
number of scripts that used the plugins. These are briefly described
below.

## Plugins

* ntp.zeek: Collects information about the NTP packets in network
  traffic or a PCAP file.  Seven log files are maintained by this
  plugin, depending on the type and contents of the NTP packets.

* ntp-stats.zeek: Gathers and calculates statistics about NTP
  traffic. The statistics are then written in a normal Zeek log
  format.

## Commands

* zeek-log.py: Displays data from a Zeek log in a much more readable
  way than can be seen by looking at logs directly.  It also provides
  shortcuts for displaying log-specific fields for some types of Zeek
  logs, though this command may be used with any Zeek log file.

* zeek-grep.py: Searches Zeek log files for specific strings. This
  script searches according to columns, but reports matching rows. For
  example, a log’s “sending address” column could be searched for
  “192.168.1.42”, and rows with that matching address would be
  displayed.

* hostxref.py: Uses Zeek log files to determine how addresses used by
  one network protocol are also used by other protocols. The default
  results consist of the multi-protocol matches, divided first by
  originator’s subnet, originator’s IP address and then by
  protocol. (This is the Zeek version of the Bro szr-hostxref.py
  script.)


# License

Copyright (c) 2021, Parsons, Corp.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

*  Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

*  Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

*  Neither the name of Parsons, Corp nor the names of its contributors may
   be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS
IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
