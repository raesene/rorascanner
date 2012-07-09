# Copyright (C) 2011  Rory McCune
#
# =License
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# =Overview
#
# This is the main class for adding scan checks to be carried out over a TNS connection.  Each module should follow
# the pattern below
#
# =Template Variables for Scan Modules
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


class RoraScanner

  begin
    require 'rubygems'
    #Need this for 1.8 compatibility
    require 'require_all'
    require 'oci8'
    require_rel 'rora_reporter'
    require 'logger'
    require 'digest/md5'
    require 'open-uri'
    require 'yaml'
    require_rel 'rora_patch_level_checks.rb'
  rescue LoadError => e
    puts "Couldn't find some of the required gem.  Most likely problems are oci8 and require_all"
    puts "For oci8 check the website for the installation process, for require_all just install the gem"
    puts e.to_s
    exit
  end


  include RoraReporter
  include RoraPatchLevelChecks
  
  attr_reader :config

  # Starts a new instance of the class, sets up the logging and makes the initial connection to the database
  def initialize(databaseUser,databasePassword,databaseConnectionString,*privilege)

    @config = File.open('scanner.conf','r') {|file| YAML::load(file)}
    @scan_log = Logger.new(@config['RoraScanner']['log_file'])
    
    case @config['RoraScanner']['log_level']
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
    
    if privilege[0] == "sysdba"
      @conn = OCI8.new(databaseUser,databasePassword,databaseConnectionString, :SYSDBA)
      @scan_log.debug("Connected to #{databaseConnectionString} as SYSDBA")
    elsif privilege[0] == "sysoper"
      @conn = OCI8.new(databaseUser,databasePassword,databaseConnectionString, :SYSOPER)
      @scan_log.debug("Connected to #{databaseConnectionString} as SYSOPER")  
    else 
      @conn = OCI8.new(databaseUser,databasePassword,databaseConnectionString)
      @scan_log.debug("Connected to #{databaseConnectionString} as user")
      
    end
    @completed_checks = Array.new
    @title = 'RoraScanner'
    #Assign the connection string to an instance variable to allow for SID checking
    @database_connection_string = databaseConnectionString
  
  rescue OCIError => e
    @scan_log.fatal("Oracle Error Encountered #{e.to_s}")
    puts 'Fatal error connection to database - ' + e.to_s
    puts 'Check Username, Password and Connection String'
    exit
  end



  # Returns the version of Oracle in use as reported by the v$version view.
  def version_scan
  
    def find_version(version_string)
      version = version_string[/\d+\.\d+\.\d+\.\d+\.\d+/]
      return version  
    end
    @version_scan_source = "rorascanner"
    @version_scan_id = "RS0001"
    @version_scan_description = "Version of Oracle running"
    @version_scan_sql = "select * from v$version"
    @version_scan_implications = " "
    @version_scan_banner = "Oracle Version"
    @version_scan_vuln_class = "Informational"
    @version_scan_version = "all"
    @version_scan_column_names = %w[Component_Name Version_Number]
    @version_scan_results = Array.new 
    @conn.exec('select * from v$version') do |r|
      if r[0]=~/Oracle/ 
	    @version_scan_results << ['ORACLE', find_version(r[0]) ]
      #Set the main version for later scans
      @version = find_version(r[0])
      @scan_log.info("version is #{@version}")
      end
      if r[0]=~/PL\/SQL/
	    @version_scan_results << ['PLSQL', find_version(r[0]) ]
      end
	  if r[0]=~/CORE/
        @version_scan_results << ['CORE', find_version(r[0]) ]
      end
      if r[0]=~/TNS/
	    @version_scan_results << ['TNS', find_version(r[0]) ]
      end
      if r[0]=~/NLSRTL/
        @version_scan_results << ['NLSRTL', find_version(r[0]) ]
      end
    end
    @completed_checks << "version_scan"
  end

  # populates the user list with username, password and account status by querying dba_users.
  def user_list_scan
   
    @dba_users = Hash.new
    @conn.exec('select username,account_status,password from dba_users') do |r|
      #Create a Hash with the username as the key and the account status and password as values
      @dba_users[r[0]]= r[1],r[2]
    end
  rescue OCIError
    @scan_log.warn("Oracle Error Encountered #{$!}")
  end

  # Reviews the results of the user list scan for known default passwords, based on the password file from petefinnigan.com
  def default_password_scan(password_file)
    @default_password_scan_source = "rorascanner"
    @default_password_scan_id = "RS0002"
    @default_password_scan_description = "This check provides a list of all the accounts with default passwords still set and the account status.  If these accounts are required the password should be altered away from the default"
    @default_password_scan_sql = ""
    @default_password_scan_implications = "Where there are accounts with default passwords it may be possible for an attacker to gain unauthorised access to the database using those credentials "
    @default_password_scan_banner = "Accounts with Default passwords set"
    @default_password_scan_vuln_class = "Account Security"
    @default_password_scan_version = "all"
    @default_password_scan_column_names = %w[Username Threat_Level Password Description Account_Status] 
    @default_password_scan_results = Array.new
    @completed_checks << "default_password_scan"
    if !@dba_users
      @scan_log.warn("User list scan has not completed so default password checking cannot be carried out.  Ensure that this is enabled in the configuration file")
      return
    end
    begin
      password_file = File.open(password_file,"a+")
      if password_file.stat.zero?
        open("http://www.petefinnigan.com/default/oracle_default_passwords.csv") do |data|
          password_file.write data.read
        end
      end
    rescue  Errno::ENOENT
      @scan_log.warn("Couldn't Open default password file " + password_file + " .  Please download from http://www.petefinnigan.com/default/oracle_default_passwords.csv and save as 'default_passwords' ")
      @default_password_scan_results << ['Warning', "Couldn't open default password file", "please review error log", " ", " "]
      
      
    end
      
    password_file.each_line do |line|  
      line = line.split(',')
      #Only run if there's a hash available for this line
      if line[4]
        #Check if this user exists by checking the dba_users hash
        if @dba_users[line[2]]
          #Compare the hashes from the default passwords list and the dba_users hash
          if line[4] == @dba_users[line[2]][1]
            #Write out a line to the default passwords hash with the username as a key 
            #and the threat level, clear test password, description of the account and the status of the account
            @default_password_scan_results << [line[2], line[1], line[3], line[5].chomp, @dba_users[line[2]][0]]
            #now remove the user here from the @dba_users hash so it's not checked for weak passwords too
            @dba_users.delete(line[2])
          end
        end
      end
    end
  end

  # Scans for weak passwords using checkpwd (location should be specified in scanner.conf
  def weak_password_scan
    @weak_password_scan_source = "rorascanner"
    @weak_password_scan_id = "RS0003"
    @weak_password_scan_description = "This check provides a list of all the accounts with weak passwords and their account status"
    @weak_password_scan_sql = ""
    @weak_password_scan_implications = "Where there are accounts with weak passwords it may be possible for an attacker to gain unauthorised access to the database using those credentials "
    @weak_password_scan_banner = "Accounts with weak passwords set"
    @weak_password_scan_vuln_class = "Account Security"
    @weak_password_scan_version = "all"
    @weak_password_scan_column_names = %w[Username Password Account_Status] 
    @weak_password_scan_results = Array.new
    
    if !@dba_users
      puts "user listing not done whoops"
      @scan_log.warn("Tried to complete weak password checking without user list. Please ensure that the user list plugin is enabled")
      exit
    end
    #TODO : Need to sort this out for windows runs 
    def check_pwd(username,password)
      if File.exists?(@config['RoraScanner']['checkpwd_location'])
        return %x{#{@config['RoraScanner']['checkpwd_location']} -quiet #{username}:#{password} #{@config['RoraScanner']['password_list_location']} }
      else
        @scan_log.warn("Couldn't find checkpwd, please confirm that this file is available and in the location specified in scanner.conf")
        return ["Error", "Couldn't find checkpwd"]
      end
    end
    @dba_users.each do |name,value|
      result = check_pwd(name,value[1])
      if result =~ /weak password/
        rarray = result.chomp.split(' has weak password ')
        rarray << value[0]
        @weak_password_scan_results << rarray
      end
    end
    @completed_checks << 'weak_password_scan'
  end

  # Scans the password profile from dba_profiles for password parameters (eg, failed_login_attempts, password life time)
  def password_profile_scan
    #TODO Need to sort out the fact that the "password verify function" test won't work at the moment.
    @password_profile_scan_source = 'CIS 8.01 - 8.06 & 8.08'
    @password_profile_scan_id = "RS0004"
    @password_profile_scan_description = 'Password profiles are important to ensure that user passwords are properly managed and also to mitigate against brute force password guessing attacks.'
    @password_profile_scan_sql = "select PROFILE,RESOURCE_NAME,LIMIT from dba_profiles WHERE resource_type = 'PASSWORD'"
    @password_profile_scan_implications = "Incorrectly set values in this section could allow for users to set passwords which don't comply with the organisations access control policy or industry good practice"
    @password_profile_scan_banner = "Password Profile"
    @password_profile_scan_vuln_class = "Account Security"
    @password_profile_scan_version = "all"
    @password_profile_scan_column_names = %w[profile_name resource_name limit desired_limit]
    @password_profile_scan_results = Array.new
    results = Array.new
    default_profile = Hash.new
    correct_profile = Hash.new
    correct_profile['FAILED_LOGIN_ATTEMPTS'] = 3
    correct_profile['PASSWORD_LIFE_TIME'] = 90
    correct_profile['PASSWORD_REUSE_MAX'] = 20
    correct_profile['PASSWORD_REUSE_TIME'] = 365
    correct_profile['PASSWORD_LOCK_TIME'] = 1
    correct_profile['PASSWORD_GRACE_TIME'] = 3
    correct_profile['PASSWORD_VERIFY_FUNCTION'] = 0
    @conn.exec(@password_profile_scan_sql) do |r|
      results << r[0] + ',' + r[1] + ',' + r[2]
    end
    #Need to sort out the DEFAULT profile stuff first before doing the remaining profiles.
    results.each do |result|
      #begin 
      if result =~/^DEFAULT/
        rsplit = result.split(',')
        default_profile[rsplit[1]] = rsplit[2]        
        if default_profile[rsplit[1]].to_s == 'UNLIMITED' || default_profile[rsplit[1]].to_i > correct_profile[rsplit[1]] 
          @password_profile_scan_results << ['DEFAULT',rsplit[1],rsplit[2],correct_profile[rsplit[1]]]
        end
        results.delete(result)
      end

    end
    
    #Should have all the DEFAULT profile stuff out of the way now so can proceed with analysing the other profile entries
    
    results.each do |result|
      
      rsplit = result.split(',')
      if rsplit[2] == 'DEFAULT'
        if default_profile[rsplit[1]].to_s == 'UNLIMITED' || default_profile[rsplit[1]].to_i > correct_profile[rsplit[1]]
          @password_profile_scan_results << [rsplit[0],rsplit[1],rsplit[2],correct_profile[rsplit[1]]]
        end
      elsif rsplit[2] == 'UNLIMITED' || rsplit[2].to_i > correct_profile[rsplit[1]]
        @password_profile_scan_results << [rsplit[0],rsplit[1],rsplit[2],correct_profile[rsplit[1]]]
      end
      
    end
  @completed_checks << 'password_profile_scan'  
  end  


# There are several parameters which are relevent to securty, in the v$parameter view.  This check scans them.
def vparameter_scan
  @vparameter_source = 'various'
  @vparameter_id = "RS0005"
  @vparameter_description = 'This section checks values from the v$parameter view against desired values specified in the CIS standard and returns exceptions.  Consider modifying these values in-line with the '
  @vparameter_sql = "select name,value from v$parameter"
  @vparameter_implications = "Where operationally possible, the parameters should be configured in-line with the recommendations from CIS"
  @vparameter_banner = "v$parameter checks"
  @vparameter_vuln_class = "Configuration Security"
  @vparameter_version = "10G,9i"
  @vparameter_column_names = %w[CIS_standard_Section parameter current_value desired_value]
  @vparameter_results = Array.new
  
  parameter_results = Hash.new
  @conn.exec(@vparameter_sql) do |r|
    parameter_results[r[0]] = r[1]
  end
  @scan_log.debug("starting parameter checks")
  #Ok now we have a hash of all the parameters from v$parameter its relatively 
  #straightforward to check against the desired values
  
  @scan_log.debug("doing global names check")
  if parameter_results['global_names'] != 'TRUE'
    @vparameter_results << ['CIS 4.02', 'GLOBAL_NAMES', parameter_results['global_names'], 'TRUE' ]
  end

  @scan_log.debug("doing max enabled roles check")
  if parameter_results['max_enabled_roles'].to_i > 30
    @vparameter_results << ['CIS 4.03', 'MAX_ENABLED_ROLES', parameter_results['max_enabled_roles'],'<30']
  end

  @scan_log.debug("doing remote_os_authent check")
  if parameter_results['remote_os_authent'] != 'FALSE'
    @vparameter_results << ['CIS 4.04', 'REMOTE_OS_AUTHENT', parameter_results['remote_os_authent'], 'FALSE']
  end
  
  @scan_log.debug("doing remote_os_roles check")
  if parameter_results['remote_os_roles'] != 'FALSE'
    @vparameter_resutls << ['CIS 4.05', 'REMOTE_OS_ROLES', parameter_results['remote_os_roles'],'FALSE']
  end

  @scan_log.debug("doing remote_listener check")
  if parameter_results['remote_listener']
    @vparameter_results << ['CIS 4.06', 'REMOTE_LISTENER', parameter_results['remote_listener'],'[NULL STRING]']
  end

  @scan_log.debug("doing audit_trail check")
  if parameter_results['audit_trail'] !=~ /OS|DB|TRUE/
    @vparameter_results << ['CIS 4.07', 'AUDIT_TRAIL', parameter_results['audit_trail'],'OS,DB or TRUE']
  end
  
  @scan_log.debug("doing os_authent_prefix check")
  if parameter_results['os_authent_prefix']
    @vparameter_results << ['CIS 4.08', 'OS_AUTHENT_PREFIX', parameter_results['os_authent_prefix'],'[NULL STRING]']
  end
  
  @scan_log.debug("doing os_roles check")
  if parameter_results['os_roles'] != 'FALSE'
    @vparameter_results << ['CIS 4.09', 'OS_ROLES', parameter_results['os_roles'],'FALSE']
  end
  
  @scan_log.debug("doing utl_file_dir check")
  if parameter_results['utl_file_dir']
    @vparameter_results << ['CIS 4.10', 'UTL_FILE_DIR', parameter_results['utl_file_dir'],'[NOT SET]']
  end
  
  @scan_log.debug("doing sql92_security check")
  if parameter_results['sql92_security'] != 'TRUE'
    @vparameter_results << ['CIS 4.13', 'SQL92_SECURITY', parameter_results['sql92_security'],'TRUE']
  end
  
  @scan_log.debug("doing o7_dictionary_accessibility check")
  if parameter_results['o7_dictionary_accessibility'] != 'FALSE'
    @vparameter_results << ['CIS 4.18', 'O7_DICTIONARY_ACCESSIBILITY', parameter_results['o7_dictionary_accessibility'],'FALSE']
  end
  
  @scan_log.debug("doing audit_sys_operations check")
  if parameter_results['audit_sys_operations'] != 'TRUE'
    @vparameter_results << ['CIS 4.20', 'AUDIT_SYS_OPERATIONS', parameter_results['audit_sys_operations'],'TRUE']
  end
  
  @scan_log.debug("doing remote_login_passwordfile check")
  if parameter_results['remote_login_passwordfile'] 
    @vparameter_results << ['CIS 4.28', 'REMOTE_LOGIN_PASSWORDFILE', parameter_results['remote_login_passwordfile'],'[NOT SET]']
  end
  
  
  @completed_checks << 'vparameter'
end


# Scans the dba_sys_privs view for excessive privileges
def sys_privs_rights_scan
  @sys_privs_rights_scan_source = 'CIS 9.x'
  @sys_privs_rights_scan_id = "RS0006"
  @sys_privs_rights_scan_description = 'Wide ranging system privileges such as SELECT ANY TABLE should be appropriately restricted.  Review the lists below to ensure that only required users have access'
  @sys_privs_rights_scan_sql = "select privilege,grantee from dba_sys_privs where privilege like '%ANY%' or privilege = 'EXEMPT ACCESS POLICY' "
  @sys_privs_rights_scan_implications = 'Excessive access rights may allow users to access or modify data that they should not have access to.'
  @sys_privs_rights_scan_banner = 'System Privileges Scan'
  @sys_privs_rights_scan_vuln_class = 'Access Rights'
  @sys_privs_rights_scan_version = 'ALL'
  @sys_privs_rights_scan_column_names = %w[grantee privileges]
  @sys_privs_rights_scan_results = Array.new
  access_rights_hash = Hash.new
  @scan_log.debug("Running sys privs scan")
  @conn.exec(@sys_privs_rights_scan_sql) do |r|
    if !access_rights_hash[r[1]]
      access_rights_hash[r[1]] = r[0]
    else
      access_rights_hash[r[1]] = access_rights_hash[r[1]] + ',' + r[0]
    end
  end
  
  @scan_log.debug("sys privs query complete adding values to results array")
  access_rights_hash.each do |key,value|
  
    @sys_privs_rights_scan_results << [key, value]
  end
  
  @completed_checks << 'sys_privs_rights_scan'
end

#Reviews a list of "sensitive" tables from the CIS standard 
def tab_privs_rights_scan
  @tab_privs_rights_scan_source = 'CIS 9.x'
  @tab_privs_rights_scan_id = 'RS0011'
  @tab_privs_rights_scan_description = 'Access to sensitive tables such as SYS.AUD$ and SYS.USER$ should be restricted to SYS and DBA users'
  @tab_privs_rights_scan_sql = 'select grantee,table_name,privilege from dba_tab_privs'
  @tab_privs_rights_scan_implications = 'Excessive access rights may allow users to access or modify data that they should not have access to.'
  @tab_privs_rights_scan_banner = 'Table Access Rights Scan'
  @tab_privs_rights_scan_vuln_class = 'Access Rights'
  @tab_privs_rights_scan_version = 'ALL'
  @tab_privs_rights_scan_column_names = %w[grantee table rights]
  @tab_privs_rights_scan_results = Array.new
  table_rights_array =Array.new
  @conn.exec(@tab_privs_rights_scan_sql) do |r|
    #This next line should remove any grants to the DBA role or the SYS user from the report as they already have full privilege to the system
    unless r[0] == 'SYS' || r[0] == 'DBA' || r[0] == 'SELECT_CATALOG_ROLE'
      #This is the list of 'sensitive' tables from the CIS standard
      #TODO: Need to find some way to clean up this line as it's really ugly
      if r[1] == 'USER$' || r[1] == 'AUD$' || r[1] == 'USER_HISTORY$' || r[1] == 'LINK$' || r[1] == 'SOURCE$' || r[1] == 'STATS$SQLTEXT' || r[1] == 'STATS$SQL_SUM' || r[1] =~ /^X\$/ || r[1] == 'DBA_ROLES'  || r[1] =~ /^V_\$/ || r[1] == 'ALL_SOURCE' || r[1] == 'DBA_SYS_PRIVS' || r[1] == 'DBA_TAB_PRIVS' || r[1] == 'DBA_ROLE_PRIVS' || r[1] == 'DBA_USERS' || r[1] == 'ROLE_ROLE_PRIVS' || r[1] == 'USER_TAB_PRIVS' || r[1] == 'USER_ROLE_PRIVS'
        table_rights_array << [r[0], r[1], r[2]]
      end
    end
  end
  table_rights_array.sort!
  table_rights_array.each do |line|
    @tab_privs_rights_scan_results << [line[0], line[1],line[2]]        
  end
  @completed_checks << 'tab_privs_rights_scan'
end

def user_role_privs_scan
  @user_role_privs_scan_source = 'CIS 9.23 & 9.41 & 9.42 & 9.43'
  @user_role_privs_scan_id = "RS0007"
  @user_role_privs_scan_description = 'There are several default roles shipped with Oracle which should not be granted to end users, as they may grant exessive privileges. Review the list below and revoke where possible'
  @user_role_privs_scan_sql = 'select username, granted_role from user_role_privs'
  @user_role_privs_scan_implications = 'Use of Oracle supplied default roles may result in users having a greater level of privileges to the database than intended'
  @user_role_privs_scan_banner = 'Role Privileges scan'
  @user_role_privs_scan_vuln_class = 'Access Rights'
  @user_role_privs_scan_version = 'ALL'
  @user_role_privs_scan_column_names = %w[user role]
  @user_role_privs_scan_results = Array.new

  @conn.exec(@user_role_privs_scan_sql) do |r|
    if r[1] =~ /CATALOG|RESOURCE|CONNECT|DBA/ && r[0] != 'SYS'
      @user_role_privs_scan_results << [r[0], r[1]]
    end
  end
  if @user_role_privs_scan_results.length > 0
    @completed_checks << 'user_role_privs_scan'
  end
end

#Reports if a default SID is being used.
def default_sid_scan
  @default_sid_scan_source = 'CIS 2.12'
  @default_sid_scan_id = "RS0008"
  @default_sid_scan_description = 'Leaving the Oracle SID at its default value makes it easier for an attacker to attach to the database and increases the susceptibility of the database to automated attacks'
  @default_sid_scan_sql = ''
  @default_sid_scan_implications = 'Default SIDs may be easily guessed by an attacker'
  @default_sid_scan_banner = 'Default SID scan'
  @default_sid_scan_vuln_class = 'Database Configuration'
  @default_sid_scan_version = 'ALL'
  @default_sid_scan_column_names = %w[SID Default?]
  @default_sid_scan_results = Array.new
  @scan_log.info("Starting Default SID scan")
  if @database_connection_string.split(/\//)[1] == 'ORCL'
    @default_sid_scan_results << ['ORCL', 'Y']
    @completed_checks << 'default_sid_scan'
  end
  @scan_log.info("completed default SID scan")
end

#Provides a list of users (other than SYS) who have the default tablespace set.
def default_tablespace_scan
  @default_tablespace_scan_source = 'CIS 9.01'
  @default_tablespace_scan_id = "RS0009"
  @default_tablespace_scan_description = 'This is a listing of all users (except SYS) who have a default tablespace of SYSTEM'
  @default_tablespace_scan_sql = 'select username,default_tablespace from dba_users'
  @default_tablespace_scan_implications = 'If users have their default tablespace of SYSTEM there is a risk of a denial of service condition occuring on the SYSTEM tablespace'
  @default_tablespace_scan_banner = 'Default Tablespace scan'
  @default_tablespace_scan_vuln_class = 'User Configuration'
  @default_tablespace_scan_version = 'ALL'
  @default_tablespace_scan_column_names = %w[User Tablespace]
  @default_tablespace_scan_results= Array.new
  
  @scan_log.info("Starting default tablespace scan")
  
  @conn.exec(@default_tablespace_scan_sql) do |r|
    if r[1] == 'SYSTEM' && r[0] != 'SYS'
      @default_tablespace_scan_results << [r[0], r[1]]
    end
  end

  if @default_tablespace_scan_results.length > 0
    @completed_checks << 'default_tablespace_scan'
  end
  
  @scan_log.info("Completed default tablespace scan")

end

#Reviews the audit profile for the database.
def audit_priv_profile_scan
  @audit_priv_profile_scan_source = 'CIS 13.03'
  @audit_priv_profile_scan_id = "RS0010"
  @audit_priv_profile_scan_description = 'This is a comparison of the system privilege audit policy on the database against the requirements of the CIS benchmark.  Review any areas where "NOT SET" is listed initially'
  @audit_priv_profile_scan_sql = 'select * from dba_priv_audit_opts'
  @audit_priv_profile_scan_implications = 'where system privileges are not audited it may be possible for a malicious user to make unauthorised modifications to the system'
  @audit_priv_profile_scan_banner = 'System Privilege Auditing'
  @audit_priv_profile_scan_vuln_class = 'Auditing'
  @audit_priv_profile_scan_version = 'ALL'
  @audit_priv_profile_scan_column_names = %w[Privilege User Success_audited? Failure_audited?]
  @audit_priv_profile_scan_results = Array.new
  priv_audit_results = Hash.new
  @conn.exec(@audit_priv_profile_scan_sql) do |r|
    if !priv_audit_results[r[2]]
      priv_audit_results[r[2]] = Array.new
      priv_audit_results[r[2]] << [r[0], r[3], r[4]]
    else 
      priv_audit_results[r[2]] << [r[0], r[3], r[4]]
    end
  end

  privs_to_audit = ['CREATE SESSION', 'ALTER ANY TABLE', 'ALTER USER','CREATE ROLE', 'CREATE USER','DROP ANY PROCEDURE','DROP ANY TABLE','GRANT ANY PRIVILEGE','GRANT ANY ROLE']
  
  privs_to_audit.each do |priv|
    if !priv_audit_results[priv]
      priv_audit_results[priv] = Array.new
      priv_audit_results[priv] << [' ','NOT SET','NOT SET']
    end
  end
  
  
  priv_audit_results.each do |key, value|
    value.each do |val|
      
      @audit_priv_profile_scan_results << [key, val[0], val[1], val[2]]
    end
  end
  
  @completed_checks << 'audit_priv_profile_scan'
 
end


end