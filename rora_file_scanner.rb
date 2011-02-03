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
#This is the main class for the file based checks that RoraScanner can perform.  These are split into checks
#on the sqlnet and listener files (tnsnames checks TBA) and file permissions checks.  The file permissions checks are
#based on the output of 'ls -al' for unix and dumpsec for windows , and basically just review for common permissions errors
#(eg, use of the everyone group for permissions in windows, and files not belonging to the oracle user in unix.
#
#If you're looking to add checks to the modules, use the template below for which variables are needed.
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
class RoraFileScanner

  require 'rubygems'
  require 'require_all'
  require_rel 'rora_reporter'
  require 'logger'
  require_rel 'rora_sqlnet_checks'
  require_rel 'rora_listener_checks'
  require_rel 'rora_tnsnames_checks'
  require_rel 'rora_file_permissions_checks'
  
  include RoraReporter
  include RoraSqlnetChecks
  include RoraTnsnamesChecks
  include RoraListenerChecks
  include RoraFilePermissionsChecks

#Initialize the class, sets up the logging level and then calls the appropriate method based on the start of the file
  def initialize(file,user,group)
    @completed_checks = Array.new
    inputArray = File.readlines(file)
    @config = File.open('scanner.conf','r') {|file| YAML::load(file)}
    @scan_log = Logger.new(@config['RoraFileScanner']['log_file'])
    
    
    case @config['RoraFileScanner']['log_level']
    when "DEBUG"
      @scan_log.level = Logger::DEBUG
    when "INFO"
      @scan_log.level = Logger::INFO
    when "WARN"
      @scan_log.level = Logger::WARN
    when "FATAL"
      @scan_log.level = Logger::FATAL
    else
      @scan_log.level = Logger::DEBUG
      @scan_log.warn("log level not set correctly using default level of DEBUG")
    end
    
    case inputArray[0]
    when /DumpSec/
      parse_windows_rights(inputArray)
      @title = 'RoraFileScanner - Windows File Rights'
    when /\.\:/
      parse_unix_rights(inputArray,user,group)
      @title = 'RoraFileScanner - Unix File Rights'
    when /^total/
      parse_unix_rights(inputArray,user,group)
      @title = 'RoraFileScanner - Unix File Rights'
    when /sqlnet\.ora/
      parse_sqlnet_file(inputArray)
      @title = 'RoraFileScanner - sqlnet.ora'
    when /listener\.ora/
      parse_listener_file(inputArray)
      @title = 'RoraFileScanner - listener.ora'
    when /tnsnames\.ora/
      parse_tnsname_file(inputArray)
      @title = 'RoraFileScanner - tnsnames.ora'
    else
      puts 'Error: Unrecognized File format'
      @scan_log.fatal("Unrecognized File format on input file")
      exit
    end
    
    
    
  rescue Errno::ENOENT, Errno::EACCES
    @scan_log.fatal("RoraScanner Error - " + $! + " Ensure target file exists and you have rights to read it")
    puts 'RoraFileScanner Error - ' + $!
    puts 'Ensure that the target file exists and you have rights to read it!'
  end
  

#Calls methods from rora_sqlnet_checks if they are set in the config hash
  def parse_sqlnet_file(inputArray)
    if @config['RoraFileScanner']['SqlnetChecks']['sql_inbound_connection_timeout_check'] == "y"
      sql_inbound_connection_timeout_check(inputArray)
    end
    if @config['RoraFileScanner']['SqlnetChecks']['sql_valid_node_check'] == "y"
      sql_valid_node_check(inputArray)
    end
    if @config['RoraFileScanner']['SqlnetChecks']['sql_invited_node_check'] == "y"
      sql_invited_node_check(inputArray)
    end
    if @config['RoraFileScanner']['SqlnetChecks']['sql_excluded_node_check'] == "y"
      sql_excluded_node_check(inputArray)
    end
    if @config['RoraFileScanner']['SqlnetChecks']['sql_expire_time_check'] == "y"
      sql_expire_time_check(inputArray)
    end
  end

#Calls methods from rora_listener_checks if they are set in the config hash
  def parse_listener_file(inputArray)

    if @config['RoraFileScanner']['ListenerChecks']['listener_logging_check'] == "y"
      listener_logging_check(inputArray)
    end
    if @config['RoraFileScanner']['ListenerChecks']['listener_admin_restrictions_check'] == "y"
      listener_admin_restrictions_check(inputArray)
    end
    if @config['RoraFileScanner']['ListenerChecks']['listener_inbound_connect_timeout_check'] == "y"
      listener_inbound_connect_timeout_check(inputArray)
    end
    if @config['RoraFileScanner']['ListenerChecks']['listener_name_check'] == "y"
      listener_name_check(inputArray)
    end
  end

#Calls methods from rora_sqlnet_checks if they are set in the config hash.  Currently unused.
  def parse_tnsnames_file(inputArray)
    #Placeholder Currently no checks implemented for tnsnames.ora
  end
end



