#!/usr/bin/env ruby
require 'socket'

ip = ARGV[0] || "0.0.0.0"
port = ARGV[1] || 4444

server = TCPServer.new(ip, port)
puts "Starting listen #{ip}:#{port}"

def hex_decode(str)
  tmp_str = ""
  str.split("\n").each{|string| string.gsub(/../) { |pair| tmp_str << pair.hex.chr }};

  return tmp_str
end

def hex_encode(str)
  str.chars.map{|x| x.ord.to_s(16)}.join
end

loop do
  Thread.start(server.accept) do |client|
    puts "Received from #{client.addr.join(":")}"
    puts "Input is ready."
    Thread.new do 
      while true
          #print ">>input:"
          command = STDIN.gets.chomp 
          cmd = hex_encode(command)
          #puts cmd
          client.puts(cmd)
      end
    end

    while true

      ready = IO.select([client], nil, nil, 10)
      if ready
        res =  client.recvfrom(40000000)[0].chomp
        #puts res.inspect
        puts hex_decode(res)
      end

    end

    #client.close
  end
end

