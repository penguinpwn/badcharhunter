
import socket
from struct import pack


def send(buffer, host, port):
    header  = b"\x75\x19\xba\xab"
    header += b"\x03\x00\x00\x00"
    header += b"\x00\x40\x00\x00"
    header += pack("<I", len(buffer))     # buffer length, 4-byte LE int
    header += pack("<I", len(buffer))     # again
    header += pack("<I", buffer[-1])      # last byte of the buffer, as an int

    request = header + buffer

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.send(request)
    finally:
        s.close()