import sys, struct, time
from itertools import * 
from more_itertools import * 
from math import sin, cos
from pwn import serialtube, context

serial = serialtube(sys.argv[1], baudrate=2000000, convert_newlines=False)
serial.newline = b'\n'
#context.log_level = 'debug'

serial.recvuntil(b"Hello?\r\n")
serial.send(b"!")
serial.recvuntil("Hello!\r\n")
N = int(serial.recvline().decode().strip())

print(f"Hello'd; N={N}")

n=N
if n%25 == 0:
	n //= 25
nn = 0

circle = cycle([(sin(i * 2 * 3.14159265 / 1000) / 2 + 0.5, cos(i * 2 * 3.14159265 / 1000) / 2 + 0.5) for i in range(1000)])

t = time.time()
i=0
while True:
	samples = take(n, circle)
	assert all(0 <= a <= 1 and 0 <= b <= 1 for a, b in samples)
 
	data = b''.join(struct.pack("<HB", int(a*728), int(b*255)) for a,b in samples)

	i += 1
	t_should_be = t + i * n / 192000 / 2

	while time.time() < t_should_be:
		pass

	serial.send(data)
	nn += n
	if nn >= N:
		nn -= N


	while time.time() < t_should_be:
		pass
