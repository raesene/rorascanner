#!/usr/bin/env ruby
#==launcher for RoraScanner
#Copyright (C) 2011  Rory McCune
#
#=License
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require 'require_all'
require 'optparse'
require_relative 'rora_scanner'




databaseUser = ""
databasePassword = ""
databaseConnectionString = ""
privilege = ""

#Little hack to get no options passed to look like "-h"
if !ARGV[0]
  ARGV[0] = "-h"
end

opts = OptionParser.new do |opts|
  opts.banner = "Usage: #$0 [OPTIONS]"

  opts.on("-uUSER", "--user USER", "Username for the database connection" ) do |u|
    databaseUser = u 
  end

  opts.on("-pPASSWORD", "--password PASSWORD", "Password for the database connection") do |p|
    databasePassword = p
  end

  opts.on("-cCONNECTION", "--connection-string CONNECTION", "Connection String for the database") do |c|
    databaseConnectionString = c
  end

  opts.on("-d", "--sysdba", :OPTIONAL, "make the connection as SYSDBA") do |d|
    privilege = "sysdba"
  end

  opts.on("-o", "--sysOper", :OPTIONAL, "make the connection as SYSOPER") do |o|
    privilege = "sysoper"
  end

  opts.on("-h", "-?", "--?", "--help", "Show this text") do
    puts opts
    exit
  end

end.parse!


scan = RoraScanner.new(databaseUser,databasePassword,databaseConnectionString,privilege)

#This is ugly need to think of a better way to do it.. hopefully avoiding eval...

if scan.config['RoraScanner']['Checks']['version_scan'] == "y"
  scan.version_scan
end

if scan.config['RoraScanner']['Checks']['user_list_scan'] == "y"
  scan.user_list_scan
end

if scan.config['RoraScanner']['Checks']['default_password_scan'] == "y"
  scan.default_password_scan("default_passwords")
end

if scan.config['RoraScanner']['Checks']['weak_password_scan'] == "y"
  scan.weak_password_scan
end

if scan.config['RoraScanner']['Checks']['password_profile_scan'] == "y"
  scan.password_profile_scan
end

if scan.config['RoraScanner']['Checks']['patch_level_scan'] == "y"
  scan.patch_level_scan
end

if scan.config['RoraScanner']['Checks']['vparameter_scan'] == "y"
  scan.vparameter_scan
end

if scan.config['RoraScanner']['Checks']['sys_privs_rights_scan'] == "y"
  scan.sys_privs_rights_scan
end

if scan.config['RoraScanner']['Checks']['tab_privs_rights_scan'] == "y"
  scan.tab_privs_rights_scan
end

if scan.config['RoraScanner']['Checks']['user_role_privs_scan'] == "y"
  scan.user_role_privs_scan
end

if scan.config['RoraScanner']['Checks']['default_sid_scan'] == "y"
  scan.default_sid_scan
end

if scan.config['RoraScanner']['Checks']['default_tablespace_scan'] == "y"
  scan.default_tablespace_scan
end

if scan.config['RoraScanner']['Checks']['audit_priv_profile_scan'] == "y"
  scan.audit_priv_profile_scan
end

scan.create_html_report(databaseConnectionString,'RoraScanner')
scan.create_csv_report(databaseConnectionString,'RoraScanner')



