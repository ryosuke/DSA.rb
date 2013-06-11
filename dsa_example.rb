#!/usr/bin/env ruby
#
#  dsa_example.rb
#
require "./dsa"

dsa = DSA.new(ARGV[0])

cve = dsa.getReferences().scan(/CVE-[0-9]+-[0-9]+/)

print "Announce: #{dsa.getDate()}\n"
print "URL: #{dsa.getURL()}\n"
print "Reference:\n"
cve.each do |c|
  print " * #{c}\n"
end

print "Details: \n \{\{\{\n #{dsa.getInformation()}\n \}\}\}\n"
