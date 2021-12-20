#! /bin/python3

import re
from pwn import *
from numpy import *

lenM = 1300
dt = .5 

p = remote('challs.xmas.htsp.ro', 6003)
p.recvuntil(b'elf>')
p.send(b'\n')
p.recvuntil(b'elf>')
p.send(b'\n')
p.recvuntil(b'yes>')
p.send(b'\n')
p.recvuntil(b'ready>')
p.send(b'\n')

while True:
    try:
        line = p.recvline().decode()
    except:
        break

    print(line)

    reg = re.compile(r"([0-9]+):\ \(((-?[0-9]*\.[0-9]*[,|)]?\ ?){2})\ ->\ \(((-?[0-9]*\.[0-9]*[,|)]?\ ?){2})")
    res = reg.match(line)

    if(res is None):
        continue

    p0 = res.group(2).split(',')
    p0[0] = float(p0[0])
    p0[1] = float(p0[1].replace(')', '').replace(' ', ''))
    p1 = res.group(4).split(',')
    p1[0] = float(p1[0])
    p1[1] = float(p1[1].replace(')', '').replace(' ', ''))
    
    dn = sqrt(p0[0]**2 + p0[1]**2)
    pn = p0
    t = 0

    while (dn > lenM):
        pn = (pn[0] + (p1[0] - p0[0]), pn[1] + (p1[1] - p0[1]))
        dn = sqrt(pn[0]**2 + pn[1]**2) 
        t+=.5

    yaw = arctan2(pn[1], pn[0]) * (180 / 3.14159)  
    t = t - (dn/900)

    yaw = round(yaw, 5)
    t = round(t, 5)
    dn = round(dn, 5)

    send = ' '.join([str(yaw), str(dn), str(t)])
    print(send)
    p.sendline((send).encode('ascii'))
