#!/usr/bin/env ruby
# -*- encoding: utf-8 -*-
#
#  dsa.rb
#
#  Author: Ryosuke KUTSUNA <ryosuke@deer-n-horse.jp>
#
require 'net/http'
require 'open-uri'
require 'nokogiri'
require 'tmpdir'
require 'tempfile'

class DSA
  def initialize(num, year=nil, lang="en")
    @dsabase = "http://www.debian.org/security"
    @cvebase = "http://web.nvd.nist.gov/view/vuln/detail?vulnId="
    @bugidbase = "bugs.debian.org/cgi-bin/bugreport.cgi?bug="

    unless num then
      puts "DSA num not exist."
      exit 1
    else
      @dsa_num = num
    end

    if year == nil then
      t = Time.new
      @year = t.year
    else
      @year = year
    end

    @lang = lang

    @tmpfile = Tempfile.new('dsa')
    getDSAHtml()
    parseDSA()
    @tmpfile.close
    @tmpfile.unlink
  end

  def getURL
    return "#{@dsabase}/#{@year}/dsa-#{@dsa_num}.#{@lang}.html"
  end

  def getDate
    return @dsa_date
  end

  def getAffected
    return @dsa_affected
  end

  def getVulnerable
    return @dsa_vulnerable
  end

  def getReferences
    return @dsa_references
  end

  def getReferencesWithURL
    text0 = @dsa_references.gsub!(/(CVE-[0-9]+-[0-9]+)/, "<a href=\"#{@cvebase}" + '\1' + "\">" + '\1' + "</a>")
    text1 = text0.gsub(/Bug ([0-9]+)/, "Bug <a href=\"#{@bugidbase}" + '\1' + "\">" + '\1' + "</a>")
    return text1
  end

  def getInformation
    return @dsa_information
  end

  private
  # get DSA Announce HTML
  def getDSAHtml() 
    dldsa = "#{@dsabase}/#{@year}/dsa-#{@dsa_num}.#{@lang}.html"
    begin
      open(dldsa) do |s|
          @tmpfile.print(s.read)
      end
    rescue => e
      p e.message
      print "Not found: #{dldsa}\n"
      exit 1
    end
  end
  
  # parse DSA Announce HTML
  def parseDSA()
    doc = Nokogiri::HTML(open(@tmpfile))
    doc.xpath('//div[@id = "content"]/dl/dt').each do |c|
      case c.text
      when "Date Reported:", "報告日時:" then
        @dsa_date = doc.xpath('//div[@id = "content"]/dl/dd')[0].text
      when "DSA Affected Packages:", "影響を受けるパッケージ:" then
        @dsa_affected =  doc.xpath('//div[@id = "content"]/dl/dd')[1].text
      when "Vulnerable:", "危険性:" then
        @dsa_vulnerable = doc.xpath('//div[@id = "content"]/dl/dd')[2].text
      when "Security database references:", "参考セキュリティデータベース:" then
        @dsa_references = doc.xpath('//div[@id = "content"]/dl/dd')[3].text
      when "More information:", "詳細:" then
        @dsa_information = doc.xpath('//div[@id = "content"]/dl/dd')[4].text
      end
    end
  end
end

### main ###
if __FILE__ == $0
  dsa = DSA.new(2668, 2013, "en")
  print "Date       : #{dsa.getDate}\n"
  print "Affected   : #{dsa.getAffected}\n"
  print "Vulnerable : #{dsa.getVulnerable}\n"
  print "References : #{dsa.getReferences}\n"
  print "Information: #{dsa.getInformation}\n"
  print "References(a) : #{dsa.getReferencesWithURL}\n"
end

# EOF
