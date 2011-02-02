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
#
#=Overview
#Checks for the listener.ora file.  This module is typically called from the RoraFileScanner class.
#
#=Template Variables for Scan Modules
# each module should be named <descriptive>_scan
# and have the following variables set for reporting
#  _source
# _description
# _sql
# _implications
# _banner
# _vuln_class
# _version
# _column_names
# _results


module RoraListenerChecks

#Check for listener logging
  def listener_logging_check(inputArray)
    @listener_logging_check_source = 'CIS 4.15 SCORE 5.01.11'
    @listener_logging_check_id = "RL0001"
    @listener_logging_check_description = 'This parameter should be set to on to ensure that the listener is logging'
    @listener_logging_check_timeout_sql = 'N/A'
    @listener_logging_check_implications = 'Listener logging should be enabled to ensure that any brute-force attacks against it are recorded.'
    @listener_logging_check_banner = 'Listener Logging'
    @listener_logging_check_vuln_class = 'listener security'
    @listener_logging_check_version = 'All'
    @listener_logging_check_column_names = %w[parameter current_value]
    @listener_logging_check_results = Array.new
    listener_logging = ''
    @scan_log.info("started Listener Logging Check")
    inputArray.each do |line|
     if line =~ /LOGGING_/
       listener_logging = line.split('=')[1].lstrip.rstrip.chomp
     end
    end
    #Listener logging is on by default
    if listener_logging == 'OFF'
      @listener_logging_check_results << ['LOGGING_', 'OFF']
      @completed_checks << 'listener_logging_check'
    end 
    @scan_log.info("Completed Listener Logging Check")
    
  end

#Check for Listener Admin restrictions
  def listener_admin_restrictions_check(inputArray)
    @listener_admin_restrictions_check_source = 'CIS 4.14 '
    @listener_admin_restrictions_check_id = "RL0002"
    @listener_admin_restrictions_check_description = 'This parameter should be set to on to restrict the commands that can be executed remotely on the listener'
    @listener_admin_restrictions_check_timeout_sql = 'N/A'
    @listener_admin_restrictions_check_implications = 'Listener admin restrictions should be enabled to restrict what settings can be changed remotely'
    @listener_admin_restrictions_check_banner = 'Listener Admin Restrictions'
    @listener_admin_restrictions_check_vuln_class = 'listener security'
    @listener_admin_restrictions_check_version = 'All'
    @listener_admin_restrictions_check_column_names = %w[parameter current_value]
    @listener_admin_restrictions_check_results = Array.new
    
    listener_admin_restrictions = 'OFF'
    @scan_log.info("Started Listener Admin Restrictions Check")
    inputArray.each do |line|
      if line =~ /^ADMIN_RESTRICTIONS/
        if line =~ /ON$/
          listener_admin_restrictions = 'ON'
        end
      end
    end
    
    if listener_admin_restrictions == 'OFF'
      @listener_admin_restrictions_check_results << ['ADMIN_RESTRICTIONS', 'OFF']
      @completed_checks << 'listener_admin_restrictions_check'
    end  
    @scan_log.info("Completed Listener Admin Restrictions Check")
  end

#Check for inbound connection timout.
  def listener_inbound_connect_timeout_check(inputArray)
    @listener_inbound_connect_timeout_check_source = 'CIS 4.21'
    @listener_inbound_connect_timeout_check_id = "RL0003"
    @listener_inbound_connect_timeout_check_description = 'Restricting the initial connection timeout helps defend against DoS attacks'
    @listener_inbound_connect_timeout_check_sql = ''
    @listener_inbound_connect_timeout_check_implications = 'Restricting this parameter helps defend against DoS attacks'
    @listener_inbound_connect_timeout_check_banner = 'Listener Connection Timeout check'
    @listener_inbound_connect_timeout_check_vuln_class = 'Listener Configuration'
    @listener_inbound_connect_timeout_check_version = 'ALL'
    @listener_inbound_connect_timeout_check_column_names = %w[parameter value]
    @listener_inbound_connect_timeout_check_results = Array.new
    timeout = 99999
    @scan_log.info("Started Listener Inbound Connection Timeout Check")
    inputArray.each do |line|
      if line =~ /^INBOUND_CONNECT_TIMEOUT/
        timeout = line.split('=')[1].lstrip.chomp.to_i
      end
    end
    
    if timeout > 2
      if timeout == 99999
        timeout = 'NOT DEFINED'
      end
      @listener_inbound_connect_timeout_check_results << ['INBOUND_CONNECT_TIMEOUT', timeout]
      @completed_checks << 'listener_inbound_connect_timeout_check'
    end
    @scan_log.info("Completed Listener Inbound Connection Timeout Check")
  
  end

#Check to ensure that the default listener name is set.
  def listener_name_check(inputArray)
    @listener_name_check_source = 'CIS 2.04'
    @listener_name_check_id = "RL0004"
    @listener_name_check_description = 'The listener should not have the default name of LISTENER set'
    @listener_name_check_sql = ''
    @listener_name_check_implications = ''
    @listener_name_check_banner = 'Listener default name check'
    @listener_name_check_vuln_class = 'Listener Configuration'
    @listener_name_check_version = 'ALL'
    @listener_name_check_column_names = %w[name default?]
    @listener_name_check_results = Array.new
  
    @scan_log.info("Started default listener name check")
  
    inputArray.each do |line|
      if line =~ /^LISTENER/
        @listener_name_check_results << ['LISTENER', 'YES']
        @completed_checks << 'listener_name_check'
      end  
    end
  @scan_log.info("Completed default listener name check")
  end  


end