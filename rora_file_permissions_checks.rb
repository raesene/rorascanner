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
#TODO: See if there are better ways to review these permissions (eg, PowerShell on windows)

module RoraFilePermissionsChecks


#Reviews a files passed with the rights setup on Oracle windows instances reviewing for use of the "everyone" group
  def parse_windows_rights(inputArray)
    @windows_file_rights_source = 'Bespoke'
    @windows_file_rights_description = 'This plugin is designed to review the rights of files in the Oracle installation looking for instances of the Everyone group'
    @windows_file_rights_sql = 'N/A'
    @windows_file_rights_implications = 'Rights to key Oracle files and directories should not be assigned to the Everyone group as this allows anyone with a valid account on the system to get access to them.'
    @windows_file_rights_banner = 'Windows File Rights'
    @windows_file_rights_vuln_class = 'File Permissions'
    @windows_file_rights_version = 'All'
    @windows_file_rights_column_names = %W[Path Rights]
    @windows_file_rights_results = Array.new
    inputArray.each do |line|
      fileArray = line.split(',')
      if fileArray.length > 1 && fileArray[1].rstrip == 'Everyone'
        @windows_file_rights_results << [fileArray[0],fileArray[2]]
      end
    end
  @completed_checks << 'windows_file_rights'
  @title = 'Windows File Rights'
  end

  

#Reviews the ownership of files in the oracle directory
  def parse_unix_rights(inputArray,user,group)
    @unix_file_rights_source = 'CIS 3.01 3.02 3.03, SCORE 1.01.01'
    @unix_file_rights_description = 'This plugin is designed to review the rights of files in the Oracle installation looking for instances where the owner is incorrectly set or users outside the dba group have access to Oracle files'
    @unix_file_rights_sql = 'N/A'
    @unix_file_rights_implications = 'Rights to key Oracle files and directories should not be assigned to users outside the dba group as this allows anyone with a valid account on the system to get access to them.'
    @unix_file_rights_banner = 'Unix File Rights'
    @unix_file_rights_vuln_class = 'File Permissions'
    @unix_file_rights_version = 'All'
    @unix_file_rights_column_names = %W[Path Permissions user group]
    @unix_file_rights_results = Array.new
    currentDirectory = '.'
    inputArray.each do |line|
      case line
      
      when /^\.\//
        currentDirectory = line.chomp.sub(/\:$/,'')
      when /^[a-zA-Z\-]{10}/
        fileArray = line.split(' ')
        rights = fileArray[0]
        fileUser = fileArray[2]
        fileGroup = fileArray[3]
        file = fileArray[8]
        
        #Eliminate the . and .. entries as they're not relevant and also eliminate links as they always have 777 permissions
        unless file == '.' || file == '..' || rights =~ /^l/
          if currentDirectory == './bin'
            #Alert on entries where the user or group don't equal the one passed or the "other" rights allow for writing to a file
            if fileUser.upcase != user.upcase || fileGroup.upcase != group.upcase || rights.slice(7..9) =~ /w/
              @unix_file_rights_results << [currentDirectory + '/' + file, rights, fileUser, fileGroup]
            end
          else
            #Alert on entries where the user or group don't equal the one passed or the "other" rights aren't 0
            if fileUser.upcase != user.upcase || fileGroup.upcase != group.upcase || rights.slice(7..9) != '---'
              @unix_file_rights_results << [currentDirectory + '/' + file, rights, fileUser, fileGroup]
            end
          end
        end
          
      end
    end
  @completed_checks << 'unix_file_rights'
  
  end
  
end 