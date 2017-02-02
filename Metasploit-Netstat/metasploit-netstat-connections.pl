# Copyright (c) 2014, butterworth1492
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#Summary:
#  It is often prudent to include netstat dumps as part of automatic Metasploit
#  post-exploitation loot that is collected upon establishing a callback.
#  This script sifts through the large amount of information in the loot file(s),
#  scrapes out the netstat information, analyzes each individual connection, 
#  and prints out information that can be useful when building a target package.
#  The output is formatted to allow for easy parsing.

#Usage:
# perl metasploit-netstat-connections.pl <file with netstat output>

#Output:
# 1. A list of every connection made.
# 2. Both endpoints, client and server, that participated in the connection
# 3. The client and server ports used in the connection


die("Usage: $0 <input file>\n") unless (@ARGV > 0);
my ($INPUT_FILE, $PORT) = @ARGV;

open(FILE, "< $INPUT_FILE") or die ("Can't open $INPUT_FILE\n");
# Print connections
while ($host = <FILE>)
  {
    if ($host =~ /\s+(ESTABLISHED|CLOSE_WAIT|TIME_WAIT)\s+([^\s]+)\s+(\d+)\s+([^\s]+)\s+(\d+)$/)
      {
        my ($host1,$port1,$host2,$port2) = ($2,$3,$4,$5);
        next if ($host1 =~ /127\.0\.0\.1/);  # Some IPs aren't complete 
        next if ($host2 =~ /127\.0\.0\.1/);  # Some IPs aren't complete 
        next if ($host1 !~ /((\d{1,3})\.){3}(\d{1,3})/);  # Some IPs aren't complete 
        next if ($host2 !~ /((\d{1,3})\.){3}(\d{1,3})/);  # Some IPs aren't complete 
        print "$host1 [$port1]\t-> $host2 [$port2]\n";
      } 
  }
close(FILE) or warn("Had issues closing $INPUT_FILE\n");



