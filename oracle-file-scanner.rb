#!/usr/bin/env ruby
#==Launcher for RoraFileScanner
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


require 'rubygems'
require 'require_all'
require 'optparse'
require_rel 'rora_file_scanner.rb'


oracleFile = ""
oracleUser = ""
oracleGroup = ""


#Little hack to get no options passed to look like "-h"
if !ARGV[0]
  ARGV[0] = "-h"
end

opts = OptionParser.new do |opts|
  opts.banner = "Usage: #$0 [OPTIONS]"
  
  opts.on("-fFILE","--file FILE", "Directory Listing or Initialization File to be parsed" ) do |f|
    oracleFile = f
  end
    
  opts.on("-uUSER","--user USER","Oracle User, only needed for Unix File Permissions Check") do |u|
    oracleUser = u
  end
  
  opts.on("-gGROUP","--group GROUP", "Oracle Group, only needed for Unix File Permissions Check") do |g|
    oracleGroup = g
  end

  opts.on("-h", "-?", "--?", "--help", "Show this text") do
    puts opts
    exit
  end
end.parse!

scan = RoraFileScanner.new(oracleFile,oracleUser,oracleGroup)

scan.create_html_report('File Scan','scan.title')
