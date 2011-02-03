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
#This module adds checks for patch level and OS that the database is running on.  Currently the patch_level_scan check
#is at alpha level with a couple of instances enabled.  It essentially looks at the md5 of packages which incdicate
#that a particular CPU has been installed.  Ideally this needs updated on a regular basis (quarterly).
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
#


module RoraPatchLevelChecks


#This is the clever way to do this.  Downside is that it needs a sig for every CPU for every platform
#At the moment I've got no access to CPUs so remove for now and replace with the dumb version.
#def patch_level_scan
#  #This only works with version 10.2.0.1 at the moment on Linux x86 and Windows...
#  detect_os_version
#  @patch_level_scan_source = 'bespoke'
#  @patch_level_scan_id = "RS0011"
#  @patch_level_scan_description = "Oracle release quarterly security updates for their Database products, it's important to ensure these updates are applied"
#  @patch_level_scan_sql = ""
#  @patch_level_scan_implications = "If critical patch updates are not applied the database is likely to have exploitable security vulnerabilities"
#  @patch_level_scan_banner = "CPU checking"
#  @patch_level_scan_vuln_class = "Patching"
#  @patch_level_scan_version = "10.2.0.1.0"
#  @patch_level_scan_column_names = ['patch_level' ,'installed?']
#  @patch_level_scan_results = Array.new
#
#  #Stop patch scan running with older versions as it won't work
#  if @version =~ /^9|8|7/
#    @scan_log.warn("tried patch level scan with version 9 or earlier database won't work!")
#    return
#  end
#
#  #Need to work out what OS we're running on.
#  if @db_os == 'Windows'
#    changed_hash = Hash.new
#    changed_hash['jan06'] = ['OWA_OPT_LOCK', 'SYS', 'cb965c814e58518c01797cd5fa06f73b']
#    changed_hash['apr06'] = ['DBMS_REGISTRY_SYS', 'SYS', '4e73794e5557fb7964e55bc59ca9d34e']
#    changed_hash['jul06'] = ['DBMS_METADATA', 'SYS', '56e718c65584449575f547f4afed6578']
#    changed_hash['oct06'] = ['DBMS_CDC_IMPDP', 'SYS', 'ddab7de3352f37c7cad4001e22234d19']
#  elsif @db_os == 'Unix'
#    changed_hash = Hash.new
#    changed_hash['jan06'] = ['OWA_OPT_LOCK', 'SYS', 'cb965c814e58518c01797cd5fa06f73b']
#    changed_hash['apr06'] = ['DBMS_REGISTRY_SYS', 'SYS', 'dda8a5bebf3615ecb0f200aedc061f78']
#    changed_hash['jul06'] = ['DBMS_METADATA', 'SYS', '1d90513fdfcc9c085534b6f7d0f21060']
#    changed_hash['oct06'] = ['DBMS_CDC_IMPDP', 'SYS', 'ddab7de3352f37c7cad4001e22234d19']
#  else
#    @scan_log.WARN("Unable to carry out patch level check as OS can't be determined")
#    return
#  end
#
#  changed_hash.each do |key,value|
#    statement = "select DBMS_METADATA.GET_DDL('PACKAGE','#{value[0]}','#{value[1]}') from DUAL"
#    @conn.exec(statement) do |r|
#      if Digest::MD5.hexdigest(r[0].read) == value[2]
#        @patch_level_scan_results << [key, 'Yes']
#      else
#        @patch_level_scan_results << [key, 'No']
#      end
#    end
#  end
#  @completed_checks << 'patch_level_scan'
#
#end

#This check reviews the dba_registry_history view to return the latest CPU installed
def patch_level_scan
  @patch_level_scan_source = 'bespoke'
  @patch_level_scan_id = "RS0011"
  @patch_level_scan_description = "Oracle release quarterly security updates for their Database products, it's important to ensure these updates are applied"
  @patch_level_scan_sql = "select version,comments from dba_registry_history"
  @patch_level_scan_implications = "If critical patch updates are not applied the database is likely to have exploitable security vulnerabilities"
  @patch_level_scan_banner = "CPU checking"
  @patch_level_scan_vuln_class = "Patching"
  @patch_level_scan_version = "10.2.0.1.0"
  @patch_level_scan_column_names = ['database_version' ,'installed_CPU']
  @patch_level_scan_results = Array.new

  @conn.exec(@patch_level_scan_sql) do |r|
    @patch_level_scan_results << [r[0], r[1]]
  end
  @completed_checks << 'patch_level_scan'


end

#A Method to return the OS that the database is running on (windows/unix)
def detect_os_version
#Work out what OS we are
#At the moment this is a bit of a hack. The hack is that file names in Windows based OS's start with an Alpha character and in Unix statr with a /
  @conn.exec('select FILE_NAME from DBA_DATA_FILES') do |r|
    if r[0] =~ /^[a-zA-Z]/
      @db_os = 'Windows'
    elsif r[0] =~ /^\//
      @db_os = 'Unix'
    else
      @scan_log.WARN("unable to determine OS")
      #TODO: move this to a thrown error to be caught elsewhere for now default to unix
      @db_os = 'Unix'
    end
  end
end

end
