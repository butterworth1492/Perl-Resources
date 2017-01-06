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


# Summary:
#   It is often prudent to include netstat dumps as part of automatic Metasploit
#   post-exploitation loot that is collected upon establishing a callback.
#   This script sifts through the large amount of information in the loot file(s),
#   scrapes out the netstat information, analyzes each individual connection, 
#   and prints out information that can be useful when building a target package.
#   The output is formatted to allow for easy parsing.

# Usage:
#  perl metasploit-netstat-ports.pl <file with netstat output> <port of interest>

# Output:
#  1. A list of every client that connected to a remote resource on that port
#  2. A list of every server that accepted a connection on that port
#  3. The number of times each client connected or each server accepted
#     a connection on that port
#  4. A breakdown of the top 5 noisiest clients and servers talking on that
#     port 


die("Usage: $0 <input file> <port>\n") unless ( @ARGV > 1);
my ($INPUT_FILE, $PORT) = @ARGV; 

#$INPUT_FILE = "src/nightmare_spray.txt";
open(FILE, "< $INPUT_FILE") or die ("Can't open $INPUT_FILE\n");

my %clients = {};
my %servers = {};

# Print connections
while ($host = <FILE>)
  {
    if ($host =~ /\s+(ESTABLISHED|CLOSE_WAIT|TIME_WAIT)\s+([^\s]+)\s+(\d+)\s+([^\s]+)\s+(\d+)$/)
      {
        my ($host1,$port1,$host2,$port2) = ($2,$3,$4,$5);
        next if ($host1 !~ /((\d{1,3})\.){3}(\d{1,3})/);  # Some IPs aren't complete 
        $re = qr/$PORT/;
        if ($port1 =~ /^${re}$/)    # I am the server
          { 
            print "[CONNECTION] $host2\t-> $host1 [$port1]\n";
	    if ( exists($clients{$host2}) ) { $clients{$host2} = $clients{$host2} + 1 }
              else { $clients{$host2} = 1 }
	    if ( exists($servers{$host1}) ) { $servers{$host1} = $servers{$host1} + 1 }
              else { $servers{$host1} = 1 }
          }
        elsif ($port2 =~ /^${re}$/)  # I am the client
          {
            print "[CONNECTION] $host1\t-> $host2 [$port2]\n";
            if ( exists($clients{$host1}) ) { $clients{$host1} = $clients{$host1} + 1 }
              else { $clients{$host1} = 1 }
	    if ( exists($servers{$host2}) ) { $servers{$host2} = $servers{$host2} + 1 }
              else { $servers{$host2} = 1 }
          }
      } 
  }
close(FILE) or warn("Had issues closing $INPUT_FILE\n");

# Print clients and servers
my @client_keys = sort { $clients{$b} <=> $clients{$a} } keys(%clients); 
foreach ( @client_keys ) # Print the noisy clients
  { print "[CLIENT] $_ [$clients{$_}]\n" if ! /HASH/; }

my @server_keys = sort { $servers{$b} <=> $servers{$a} } keys(%servers); 
foreach ( @server_keys ) # Print the popular servers
  { print "[SERVER] $_ [$servers{$_}]\n" if ! /HASH/; }

# Print results
$size = keys(%clients);
print "[RESULT] Total clients: " . ($size-1) . "\n";
$size = keys(%servers);
print "[RESULT] Total servers: " . ($size-1) . "\n";

if ( @client_keys > 1 )
  {
    foreach ( @client_keys[0..4] )
      { print "[RESULT] Top clients: $_ [" . $clients{$_} . "]\n"; }
  }
if ( @server_keys > 1 )
  {
    foreach ( @server_keys[0..4] )
      { print "[RESULT] Top servers: $_ [" . $servers{$_} . "]\n"; }
  }
