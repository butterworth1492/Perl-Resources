# Copyright (c) 2016, butterworth1492
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
#   Enumerating domain users can be a challenge as there can sometimes be
#   *too* much information.  This script consumes a JSON-formatted LDAP a
#   dump file and parses the information out into readable categories
#   for LDAP users, roles, and groups.

# Usage:
#  perl ldap-user-enum.pl <json output>

# Output:
#     1. Users and their roles/groups
#     2. Roles and their users
#     3. Groups and their users

$INPUT_FILE = "Users.txt";
open(FILE, "< $INPUT_FILE") or die ("Can't open $INPUT_FILE\n");

my @users;
my %role;
my %groups;

while (<FILE>)
  {
    %user;
    my @users_groups;

    $user{name} = $1;

    $role = (/description":"([^"]+)/i) ? $1 : "*NO ROLE*";
    $user{role} = $role; 
    $roles{$role} = "";

    while (/DC=mil\^CN=([^,]+)/g )
      { 
        push(@users_groups, $1); 
        $groups{$1} = "";
      }

    $user{groups} = [@users_groups];         # Expl: Copy value of local array

    push(@users, {%user});                   # Expl: Copy value of local hash
  } 
close(FILE) or warn("Couldn't close $INPUT_FILE\n");

# User/Role/Groups
for ( @users )
  {
    my %user = %{$_};                # Expl: Casting reference as hash
    print "[USER]|" . $user{name} . "|";
    print $user{role} . "|";
    my @groups = @{$user{groups}};   # Expl: Casting reference as array
    print join(",", @groups);
    print "\n";
  }

# Role/Users
for my $role ( sort(keys(%roles)) )
  {
    my @users_with_role;
    print "[ROLE]|" . $role . "|";
    for ( @users )
      {
        my %user = %{$_};
        push(@users_with_role, $user{name}) if ( $user{role} eq $role );
      }     
    print join(",", @users_with_role) . "\n";
  }

# Group/Users
for my $group ( sort(keys(%groups)) )
  {
    my @users_in_group;
    print "[GROUP]|" . $group . "|";
    for ( @users )
      {
        my %user = %{$_};
        my @groups = @{$user{groups}};
        for ( @groups )
          { push(@users_in_group, $user{name}) if ($_ eq $group) }
       }
    print join(",", @users_in_group) . "\n";
  }
