import wave, sys, struct, time
from pwn import serialtube, context

serial = serialtube(sys.argv[1], baudrate=115200, convert_newlines=False)
serial.newline = b'\n'
#context.log_level = 'debug'

wav = wave.open(sys.argv[2], "rb")

serial.recvuntil(b"Hello?\r\n")
serial.send(b"!")
serial.recvuntil("Hello!\r\n")
N = int(serial.recvline().decode().strip())

print(f"Hello'd; N={N}")

n=N
nn = 0

t = time.time()
for _ in range(wav.getnframes() // n):
	samples = [(a / 65536 + 0.5, b / 65536 + 0.5) for a, b in struct.iter_unpack("hh", wav.readframes(n))]
	assert all(0 <= a <= 1 and 0 <= b <= 1 for a, b in samples)
 
	data = b''.join(struct.pack("<HB", int(a*728), int(b*256)) for a,b in samples)

	serial.send(data)
	nn += n
	if nn >= N:
		nn -= N
		#time.sleep(0.1)
