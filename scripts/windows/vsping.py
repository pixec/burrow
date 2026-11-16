"""Prints the hybrid vsock's answer to `CONNECT 1024`: `OK <port>` once the agent listens."""
import socket
import sys

s = socket.socket(socket.AF_UNIX)
s.settimeout(3)
try:
    s.connect(sys.argv[1])
    s.sendall(b"CONNECT 1024\n")
    print(s.recv(64).decode().strip())
except OSError as e:
    print("no:", e)
