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
#This module adds the two reporting methods (HTML and CSV).  the HTML report makes use of builder to create the file
#The CSV report uses the STDLIB csv class.


module RoraReporter



require 'rubygems'

#Creates an HTML report
def create_html_report(server,checkType)
  require 'builder'
  require 'ruport'
  
  filename = server.sub(/\//,'-') + Time.now.gmtime.to_s.gsub(/\W/,'') + ".html"
  report = File.new(filename, "w+")
  
  
  xmlBuild = Builder::XmlMarkup.new(:target => report, :indent => 2 )
  
  xmlBuild.instruct!
  xmlBuild.declare! :DOCTYPE, :html, :PUBLIC, "-//W3C//DTD XHTML 1.0 Strict//EN", "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"
  
  xmlBuild.html( "xmlns" => "http://www.w3.org/1999/xhtml" ) { 

    xmlBuild.head { 
      xmlBuild.title @title + 'report for ' + server
      xmlBuild.style( "type"=>"text/css" ) { xmlBuild.text! "h1 {font-family:tahoma,sans-serif;font-size:18pt;color:blue} body{font-family:georgia,serif} #banner{font-family:georgia,serif;font-size:14pt;color:green} table{background-color: #999; border: 1px solid black;} th {color: white; background-color: #333; } td {background-color: #ccc; border: 1px solid black;} .hidden { display:none; } .unhidden { display:block; }" 
      }
      xmlBuild.script( "type"=>"text/javascript") {xmlBuild.text! "
       function unhide(divID) {
         var item = document.getElementById(divID);
         if (item) {
           item.className=(item.className=='hidden')?'unhidden':'hidden';
         }
       }" 
      }
    } 
    
    xmlBuild.body {
      xmlBuild.h1 @title + ' report for ' + server + '- Created on ' + DateTime.now.to_s
      @completed_checks.each do |check|
        table_results = eval %{@#{check}_results}
        source = eval %{@#{check}_source}
        description = eval %{@#{check}_description}
        sql = eval %{@#{check}_sql}
        implications = eval %{@#{check}_implications}
        banner = eval %{@#{check}_banner}
        vuln_class = eval %{@#{check}_vuln_class}
        version = eval %{@#{check}_version}
        column_names = eval %{@#{check}_column_names}
        table = Ruport::Data::Table.new :data => table_results, :column_names => column_names
        xmlBuild.br
        xmlBuild.p(:id => "banner") {
          xmlBuild.a(banner, "href"=>"javascript:unhide('#{check}')")
       }
        xmlBuild.div(:id => check, :class => "hidden") {
        xmlBuild.p {
          xmlBuild.b "Check Source" 
          xmlBuild.text! " : " + source
        }
        xmlBuild.p { 
          xmlBuild.b "Vulnerability Class"
          xmlBuild.text! " : " + vuln_class
        } 
        xmlBuild.p {
          xmlBuild.b "Check Description"
          xmlBuild.text! " : " + description
        }
        if implications.length > 1
          xmlBuild.p {
            xmlBuild.b "Check Implications"
            xmlBuild.text! " : " + implications
          }
        end
        report << table.to_html
        }
      end
    }
  }
end

#Creates CSV report
def create_csv_report(server,checkType)
  require 'csv'
  filename = server.sub(/\//,'-') + Time.now.gmtime.to_s.gsub(/\W/,'') + ".csv"
  report = File.new(filename, "w+")
  report.puts "# CSV report for " + server + "created at " + Time.now.gmtime.to_s
  
  @completed_checks.each do |check|
    scan_id = eval %{@#{check}_id}
    banner = eval %{@#{check}_banner}

    report.puts "# " + scan_id + " " + banner 
    header = eval %{@#{check}_column_names}
    report.puts CSV.generate_line(header)
    body = eval %{@#{check}_results}
    body.each do |line|
      report.puts CSV.generate_line(line)
    end
  end
  
  
  
 
end  


end