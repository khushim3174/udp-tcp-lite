import socket
import struct
import time
import random

SERVER = ("127.0.0.1", 9000)
BUF = 4096
HDR_FMT = "!I I B H H"
HDR_SIZE = struct.calcsize(HDR_FMT)
TIMEOUT = 1.0
MAX_RETRIES = 5

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

def send_and_wait(sock, pkt, expected_flags=None, expected_ack=None, timeout=TIMEOUT):
    attempts = 0
    while attempts < MAX_RETRIES:
        sock.sendto(pkt, SERVER)
        sock.settimeout(timeout)
        try:
            raw, _ = sock.recvfrom(BUF)
            r = unpack_packet(raw)
            if r is None:
                attempts += 1
                continue
            if expected_flags and not (r["flags"] & expected_flags):
                attempts += 1
                continue
            if expected_ack is not None and r["ack"] != expected_ack:
                attempts += 1
                continue
            return r
        except socket.timeout:
            attempts += 1
            print(f"[client] timeout waiting (attempt {attempts}/{MAX_RETRIES})")
    return None

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_isn = random.randint(0, 0x7fffffff)
    syn_pkt = pack_packet(client_isn, 0, FLAG_SYN, 1, b'')
    print(f"[client] sending SYN seq={client_isn}")
    r = send_and_wait(sock, syn_pkt, expected_flags=FLAG_SYN|FLAG_ACK)
    if not r:
        print("[client] handshake failed (no SYN-ACK)")
        return
    server_isn = r["seq"]
    print(f"[client] got SYN-ACK sseq={server_isn} sack={r['ack']}")
    ack_pkt = pack_packet(client_isn + 1, server_isn + 1, FLAG_ACK, 1, b'')
    sock.sendto(ack_pkt, SERVER)
    print("[client] sent ACK. connection established.")
    payload = b"Hello from client (reliable over UDP)!"
    data_pkt = pack_packet(client_isn + 1, server_isn + 1, FLAG_PSH, 1, payload)
    print("[client] sending data...")
    ack_response = send_and_wait(sock, data_pkt, expected_flags=FLAG_ACK, expected_ack=len(payload) + (client_isn + 1))
    if ack_response:
        print(f"[client] received ACK for data ack={ack_response['ack']}")
    else:
        print("[client] failed to get ACK for data after retries")
    fin_pkt = pack_packet(client_isn + 1, server_isn + 1, FLAG_FIN, 1, b'')
    print("[client] sending FIN")
    r = send_and_wait(sock, fin_pkt, expected_flags=FLAG_ACK)
    if r:
        print("[client] FIN ACK received; waiting for server FIN")
        try:
            sock.settimeout(3.0)
            raw, _ = sock.recvfrom(BUF)
            rp = unpack_packet(raw)
            if rp and (rp["flags"] & FLAG_FIN):
                print("[client] received server FIN; sending final ACK and closing")
                final_ack = pack_packet(client_isn + 2, rp["seq"] + 1, FLAG_ACK, 1, b'')
                sock.sendto(final_ack, SERVER)
        except socket.timeout:
            print("[client] timeout waiting for server FIN (closing anyway)")
    else:
        print("[client] did not get FIN-ACK; closing anyway")
    sock.close()

if __name__ == "__main__":
    main()
