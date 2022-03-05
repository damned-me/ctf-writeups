---
layout: post
title: Santa's Flakpanzerkampfwagen
author: damned-me
date: 2021-12-14
category: misc 
tags:
    - x-mas
    - python
---

CTF : [X-MAS CTF 2021 First Weekend][ctf_event]

Despite the name it was a relatively easy one. The problem can be resumed to "we are a turrets in (0, 0), all around us planes can spawn. We know the starting positions of the planes and the corresponding coordinates after 0.5 time units (TU). Shoot 'em."

With "shoot 'em" I mean: give as output for each given plane `<yaw> <distance> <delay>`.

- `yaw` refers to the rotation around the OZ axis, or the trigonometric angle with the positive side of the OX axis (in degrees).
- `distance` is the distance from the origin that our shell need to travel before "exploding" (in space units, SU)
- Last, we need to specify the `delay`, in TU from timestamp 0, to wait before shoot (the cannon will sort commands in a way that make sense before executing it). Inserting commands require 0 TU.

Our cannon have a range of `1300  SU`, the planes must stay at least `1000 SU` away from us (from the origin).

All the planes will spawn at `2000 SU` from us. As time passes they will get closer but without necessarily pointing directly to the origin.

So, time for some maths!

An easy way to get the job done is tracing the direction of the plane until it get in range in order to calculate the trajectory. An easy way to do this is using the following snippet:

```python
# p0    = spawn point
# p1    = point after .5 TU
# dn    = distance from origin
# lenM  = cannon range
# t     = time

lenM = 1300
dn   = sqrt(p0[0]**2 + p0[1]**2)
pn   = p0
t    = 0

# P = (p.x + (p1.x - p0.y), p.y + (p1.y - p0.y0))
# D = sqrt(p.x**2 + p.y**2)
# T = T(p1) - T(p0) = 0.5 - 0

while (dn > lenM):
    pn = (pn[0] + (p1[0] - p0[0]), pn[1] + (p1[1] - p0[1]))
    dn = sqrt(pn[0]**2 + pn[1]**2) # new distance from origin
    t  += .5
```

Where `p0` is the starting point, `p1` the point after `0.5 TU` and `pn` is the new point (fist initialized to `p0`).

We can then divide the distance of `pn` from the origin by the speed of the shell (`900 SU/TU`, given as hint of the challenge) and subtract it at the time passed `t`.

```python
t = t - (dn / 900)
```

Now that we have the point to aim for and the distance we can obtain the yaw in randians interpreting the 2 coordinates of `pn` as a vector `(x, y)` and then using the `arctan2` function as follow:

```python
yaw = arctan2(pn[1], pn[0]) * (180 / 3.14159) 
```

Note the conversion from radians to degrees with `180 / 3.14159`.

As the challenge's description says

> The shells have a *decent* blast radius, so you do not need to be pinpoint accurate.

So, if we want, we can also round up the results as follow

```python
yaw = round(yaw, 5)
t   = round(t, 5)
dn  = round(dn, 5)
```

We can then iterate every given plane at each level and than get the flag!

[The complete code][solve]:

```python
#! /bin/python3

import re
from pwn import *
from numpy import *

lenM = 1300
dt   = .5

regex = r"([0-9]+):\ \(((-?[0-9]*\.[0-9]*[,|)]?\ ?){2})\ ->\ \(((-?[0-9]*\.[0-9]*[,|)]?\ ?){2})"
reg = re.compile(regex)

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

    res = reg.match(line)
    
    if(res is None):
        continue

    p0 = res.group(2).split(',')
    p1 = res.group(4).split(',')
    
    p0[0] = float(p0[0])
    p0[1] = float(p0[1].replace(')', '').replace(' ', ''))
    p1[0] = float(p1[0])
    p1[1] = float(p1[1].replace(')', '').replace(' ', ''))
    
    dn = sqrt(p0[0]**2 + p0[1]**2)
    pn = p0
    t = 0

    while (dn > lenM):
        pn = (pn[0] + (p1[0] - p0[0]), pn[1] + (p1[1] - p0[1]))
        dn = sqrt(pn[0]**2 + pn[1]**2) 
        t += dt

    yaw = arctan2(pn[1], pn[0]) * (180 / 3.14159)  
    t = t - (dn/900)

    yaw = round(yaw, 5)
    t   = round(t, 5)
    dn  = round(dn, 5)

    send = ' '.join([str(yaw), str(dn), str(t)])
    print(send)
    p.sendline((send).encode('ascii'))
```

I used [pwntools][pwntools_link] for communications and [numpy][numpy_link] to perform the maths, than the standard python's regex library to parse inputs.

After running the script and defending the position, the program will print out our flag:

`X-MAS{4NY_PR0bl3m_c4n_B3_S0lv3d_W17h_4_b16_3n0u6H_C4NN0N_hj9jh98j94}`

[solve]: ./solve.py
[numpy_link]: https://numpy.org
[pwntools_link]: https://github.com/Gallopsled/pwntools
[ctf_event]:https://ctftime.org/event/1520
