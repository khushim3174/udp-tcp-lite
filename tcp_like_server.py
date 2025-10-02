import socket
import struct
import threading
import time
import random

ADDR = ("127.0.0.1", 9000)
BUF = 4096
TIMEOUT = 5.0

HDR_FMT = "!I I B H H"
HDR_SIZE = struct.calcsize(HDR_FMT)

FLAG_SYN = 0x01
FLAG_ACK = 0x02
FLAG_FIN = 0x04
FLAG_PSH = 0x08

def checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data), 2):
        word = data[i:i+2]
        if len(word) == 1:
            word += b'\x00'
        s += (word[0] << 8) + word[1]
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def pack_packet(seq, ack, flags, wnd, payload: bytes) -> bytes:
    payload_len = len(payload)
    hdr = struct.pack(HDR_FMT, seq, ack, flags, wnd, payload_len)
    body = hdr + payload
    cks = checksum(body)
    return body + struct.pack("!H", cks)

def unpack_packet(raw: bytes):
    if len(raw) < HDR_SIZE + 2:
        return None
    hdr = raw[:HDR_SIZE]
    seq, ack, flags, wnd, payload_len = struct.unpack(HDR_FMT, hdr)
    payload = raw[HDR_SIZE:HDR_SIZE+payload_len]
    cks_recv = struct.unpack("!H", raw[HDR_SIZE+payload_len:HDR_SIZE+payload_len+2])[0]
    calc = checksum(raw[:HDR_SIZE+payload_len])
    if calc != cks_recv:
        return None
    return {"seq": seq, "ack": ack, "flags": flags, "wnd": wnd, "payload": payload}

class TCPLikeServer:
    def __init__(self, addr):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(addr)
        self.connections = {}
        print(f"[server] listening on {addr}")

    def start(self):
        while True:
            raw, peer = self.sock.recvfrom(BUF)
            pkt = unpack_packet(raw)
            if pkt is None:
                print("[server] dropping bad packet (checksum/size)")
                continue
            threading.Thread(target=self._handle_packet, args=(pkt, peer)).start()

    def _handle_packet(self, pkt, peer):
        flags = pkt["flags"]
        if flags & FLAG_SYN:
            print(f"[server] SYN received from {peer} seq={pkt['seq']}")
            server_isn = random.randint(0, 0x7fffffff)
            state = {
                "peer_seq": pkt["seq"],
                "server_seq": server_isn,
                "expected_seq": pkt["seq"] + 1,
                "established": False
            }
            self.connections[peer] = state
            synack = pack_packet(server_isn, pkt["seq"] + 1, FLAG_SYN | FLAG_ACK, 1, b'')
            self.sock.sendto(synack, peer)
            print(f"[server] SYN-ACK -> {peer} sseq={server_isn} sack={pkt['seq']+1}")
            return
        if peer not in self.connections:
            print(f"[server] packet from unknown peer {peer}, ignoring")
            return
        state = self.connections[peer]
        if (pkt["flags"] & FLAG_ACK) and not state["established"]:
            if pkt["ack"] == state["server_seq"] + 1:
                state["established"] = True
                print(f"[server] connection established with {peer} (peer_seq={pkt['seq']})")
            else:
                print("[server] unexpected ACK during handshake")
            return
        if state["established"]:
            if pkt["flags"] & FLAG_PSH or len(pkt["payload"])>0:
                seq = pkt["seq"]
                if seq == state["expected_seq"]:
                    data = pkt["payload"]
                    print(f"[server] received DATA from {peer}: {data.decode(errors='replace')}")
                    state["expected_seq"] += len(data)
                    ack_pkt = pack_packet(state["server_seq"], state["expected_seq"], FLAG_ACK, 1, b'')
                    self.sock.sendto(ack_pkt, peer)
                    print(f"[server] ACK -> {peer} ack={state['expected_seq']}")
                else:
                    ack_pkt = pack_packet(state["server_seq"], state["expected_seq"], FLAG_ACK, 1, b'')
                    self.sock.sendto(ack_pkt, peer)
                    print(f"[server] out-of-order: expected {state['expected_seq']} got {seq}. Re-ACK sent.")
                return
            if pkt["flags"] & FLAG_FIN:
                print(f"[server] FIN received from {peer}")
                state["expected_seq"] += 1
                ack_pkt = pack_packet(state["server_seq"], state["expected_seq"], FLAG_ACK, 1, b'')
                self.sock.sendto(ack_pkt, peer)
                time.sleep(0.2)
                fin_pkt = pack_packet(state["server_seq"], state["expected_seq"], FLAG_FIN, 1, b'')
                self.sock.sendto(fin_pkt, peer)
                print(f"[server] FIN -> {peer}, closing connection")
                del self.connections[peer]
                return

if __name__ == "__main__":
    s = TCPLikeServer(ADDR)
    s.start()
