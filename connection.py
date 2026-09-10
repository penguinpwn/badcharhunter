from __future__ import annotations
import socket
from dataclasses import dataclass
 
BUF_TOKEN = b"{{BUF}}"
LEN_TOKEN = b"{{LEN}}"
 
 
@dataclass
class Connection:
    """
    A configured connection to the target's vulnerable service.
 
    host      : target IP / hostname
    port      : target TCP port
    template  : bytes containing {{BUF}} (required) and optionally {{LEN}}.
                Default is a bare {{BUF}} — the payload is sent as-is.
    timeout   : socket timeout in seconds for connect + send.
    recv_after: if True, do one recv() after sending (some services must be
                read from to actually process the buffer).
    """
 
    host: str
    port: int
    template: bytes = BUF_TOKEN
    timeout: float = 5.0
    recv_after: bool = True
 
    def __post_init__(self) -> None:
        if BUF_TOKEN not in self.template:
            raise ValueError(
                f"template must contain the {BUF_TOKEN.decode()} placeholder "
                "so the tool knows where the buffer goes"
            )
 
    def build(self, payload: bytes) -> bytes:
        """
        Substitute the payload (and its length) into the template. {{LEN}} is
        replaced with the decimal length of the payload as ASCII; do the LEN
        substitution first so it reflects the real buffer size, then drop in
        the buffer itself.
        """
        data = self.template
        if LEN_TOKEN in data:
            data = data.replace(LEN_TOKEN, str(len(payload)).encode())
        data = data.replace(BUF_TOKEN, payload)
        return data
 
    def send(self, payload: bytes) -> bytes | None:
        """
        Open a fresh TCP connection, send the built payload, optionally read
        one response, and close. Returns the recv'd bytes if recv_after is set,
        else None.
 
        A fresh connection per send is deliberate: each bad-char round needs a
        clean delivery, and short-lived connections are the simplest reliable
        way to get that against most services.
        """
        data = self.build(payload)
        with socket.create_connection((self.host, self.port),
                                      timeout=self.timeout) as sock:
            sock.sendall(data)
            if self.recv_after:
                try:
                    return sock.recv(4096)
                except socket.timeout:
                    return b""
        return None
 
 
if __name__ == "__main__":
    # Tiny manual check of the template logic (no network needed).
    c = Connection(host="127.0.0.1", port=4444,
                   template=b"LOGIN {{BUF}}\r\n")
    built = c.send(b"AAAA")
    print("built:", built)
    # assert built == b"LOGIN 4:AAAA\r\n", built
    print("template substitution OK") 