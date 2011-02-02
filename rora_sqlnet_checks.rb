# Copyright (C) 2011  Rory McCune
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
#
#
#=Template Variables for Scan Modules
# each module should be named <descriptive>_scan
# and have the following variables set for reporting
# * _source
# * _description
# * _sql
# * _implications
# * _banner
# * _vuln_class
# * _version
# * _column_names
# * _results





module RoraSqlnetChecks

#Checks the sqlnet.inbound_connect_timeout parameter
  def sql_inbound_connection_timeout_check(inputArray)
    @sql_inbound_connection_timeout_check_source = 'CIS 4.25'
    @sql_inbound_connection_timeout_check_description = 'The suggestion is to set this parameter to a low initial value (3) and then increase if necessary'
    @sql_inbound_connection_timeout_check_sql = 'N/A'
    @sql_inbound_connection_timeout_check_implications = 'Not setting this parameter may allow for a Denial of service on the database by starting connections to the database but not completing them'
    @sql_inbound_connection_timeout_check_banner = 'Inbound Connection Timeout'
    @sql_inbound_connection_timeout_check_vuln_class = 'sqlnet configuration'
    @sql_inbound_connection_timeout_check_version = 'All'
    @sql_inbound_connection_timeout_check_column_names = %w[parameter current_value]
    @sql_inbound_connection_timeout_check_results = Array.new
    connect_timeout = 99999
    @scan_log.info("Started sql inbound connection timeout check")
    inputArray.each do |line|
     if line =~ /^sqlnet\.inbound_connect_timeout/
       connect_timeout = line.split('=')[1].lstrip.rstrip.chomp
     end
    end
    if connect_timeout == 99999
      @sql_inbound_connection_timeout_check_results << ['sqlnet.inbound_connect_timeout', 'NOT SET']
      @completed_checks << 'sql_inbound_connection_timeout_check'
    elsif connect_timeout > 3
      @sql_inbound_connection_timeout_check_results << ['sqlnet.inbound_connect_timeout', connect_timeout]
      @completed_checks << 'sql_inbound_connection_timeout_check'
    end 
  end

#Check if tcp.validnode_checking is enabled in the file
  def sql_valid_node_check(inputArray)
    @sql_valid_node_check_source = 'CIS 4.22'
    @sql_valid_node_check_description = 'TBC'
    @sql_valid_node_check_sql = 'NA'
    @sql_valid_node_check_implications = 'TBC'
    @sql_valid_node_check_banner = 'Valid Node Checking'
    @sql_valid_node_check_vuln_class = 'sqlnet configuration'
    @sql_valid_node_check_version = 'ALL'
    @sql_valid_node_check_column_names = %w[parameter value]
    @sql_valid_node_check_results = Array.new
    tcpvalidnode = ''
    inputArray.each do |line|
      if line =~ /tcp.validnode_checking/
        tcpvalidnode = line.split('=')[1].downcase.lstrip.chomp
      end
    end
    if tcpvalidnode == ''
      @sql_valid_node_check_results << ['tcp.validnode_checking', 'NOT SET']
      @completed_checks << 'sql_valid_node_check'
    elsif tcpvalidnode == 'false'
      @sql_valid_node_check_results << ['tcp.validnode_checking', 'FALSE']
      @completed_checks << 'sql_valid_node_check'
    end
  end

  #Checks if tcp.invited_nodes is setup
  def sql_invited_node_check(inputArray)
    @sql_invited_node_check_source = 'CIS 4.23'
    @sql_invited_node_check_description = 'TBC'
    @sql_invited_node_check_sql = 'NA'
    @sql_invited_node_check_implications = 'TBC'
    @sql_invited_node_check_banner = 'Valid Node Checking'
    @sql_invited_node_check_vuln_class = 'sqlnet configuration'
    @sql_invited_node_check_version = 'ALL'
    @sql_invited_node_check_column_names = %w[parameter value]
    @sql_invited_node_check_results = Array.new
    tcpinvitednode = ''
    inputArray.each do |line|
      if line =~ /tcp.invited_nodes/
        tcpinvitednode = line.split('=')[1].downcase.lstrip.chomp
      end
    end
    if tcpinvitednode == ''
      @sql_invited_node_check_results << ['tcp.invited_nodes', 'NOT SET']
      @completed_checks << 'sql_invited_node_check'
    elsif tcpinvitednode == 'false'
      @sql_invited_node_check_results << ['tcp.invited_nodes', 'FALSE']
      @completed_checks << 'sql_invited_node_check'
    end
  end

  #Checks if tcp.excluded_nodes is setup.
  def sql_excluded_node_check(inputArray)
    @sql_excluded_node_check_source = 'CIS 4.24'
    @sql_excluded_node_check_description = 'TBC'
    @sql_excluded_node_check_sql = 'NA'
    @sql_excluded_node_check_implications = 'TBC'
    @sql_excluded_node_check_banner = 'Valid Node Checking'
    @sql_excluded_node_check_vuln_class = 'sqlnet configuration'
    @sql_excluded_node_check_version = 'ALL'
    @sql_excluded_node_check_column_names = %w[parameter value]
    @sql_excluded_node_check_results = Array.new
    tcpexcludednode = ''
    inputArray.each do |line|
      if line =~ /tcp.excluded_nodes/
        tcpexcludednode = line.split('=')[1].downcase.lstrip.chomp
      end
    end
    if tcpexcludednode == ''
      @sql_excluded_node_check_results << ['tcp.excluded_nodes', 'NOT SET']
      @completed_checks << 'sql_excluded_node_check'
    elsif tcpexcludednode == 'false'
      @sql_excluded_node_check_results << ['tcp.excluded_nodes', 'FALSE']
      @completed_checks << 'sql_excluded_node_check'
    end
  end

  #Checks if sqlnet.expire_time is set
  def sql_expire_time_check(inputArray)
    @sql_expire_time_check_source = 'CIS 4.26'
    @sql_expire_time_check_description = 'The suggestion is that this should be set to 10'
    @sql_expire_time_check_sql = 'N/A'
    @sql_expire_time_check_implications = 'TBC'
    @sql_expire_time_check_banner = 'Expire Time'
    @sql_expire_time_check_vuln_class = 'sqlnet configuration'
    @sql_expire_time_check_version = 'All'
    @sql_expire_time_check_column_names = %w[parameter current_value]
    @sql_expire_time_check_results = Array.new
    expire_time = 99999
    @scan_log.info("Started sql expire time check")
    inputArray.each do |line|
     if line =~ /^sqlnet\.expire_time/
       expire_time = line.split('=')[1].lstrip.rstrip.chomp
     end
    end
    if expire_time == 99999
      @sql_expire_time_check_results << ['sqlnet.expire_time', 'NOT SET']
      @completed_checks << 'sql_expire_time_check'
    elsif expire_time > 10
      @sql_expire_time_check_results << ['sqlnet.expire_time', expire_time]
      @completed_checks << 'sql_expire_time_check'
    end 
  end
  
end