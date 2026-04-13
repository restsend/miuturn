import socket
import struct
import hmac
import hashlib
import random
import time
import select
import sys
import argparse
from datetime import datetime

def log(msg):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    print(f"[{now}] {msg}")

STUN_MAGIC_COOKIE = 0x2112A442

# STUN Message Types
MSG_BINDING_REQUEST             = 0x0001
MSG_BINDING_RESPONSE            = 0x0101
MSG_ALLOCATE_REQUEST            = 0x0003
MSG_ALLOCATE_RESPONSE           = 0x0103
MSG_CREATE_PERMISSION_REQUEST   = 0x0008
MSG_CREATE_PERMISSION_RESPONSE  = 0x0108
MSG_SEND_INDICATION             = 0x0016
MSG_DATA_INDICATION             = 0x0017

# STUN Attribute Types
ATTR_MAPPED_ADDRESS       = 0x0001
ATTR_USERNAME             = 0x0006
ATTR_MESSAGE_INTEGRITY    = 0x0008
ATTR_ERROR_CODE           = 0x0009
ATTR_REALM                = 0x0014
ATTR_NONCE                = 0x0015
ATTR_XOR_MAPPED_ADDRESS   = 0x0020
ATTR_REQUESTED_TRANSPORT  = 0x0019
ATTR_XOR_PEER_ADDRESS     = 0x0012
ATTR_DATA                 = 0x0013
ATTR_XOR_RELAYED_ADDRESS  = 0x0016
ATTR_SOFTWARE             = 0x8022


def parse_addr(addr_str):
    host, port = addr_str.rsplit(':', 1)
    port = int(port)
    # Strip possible IPv6 brackets
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    return (host, port)


class StunTurnClient:
    def __init__(self, server_addr):
        self.server_addr = server_addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 0))
        self.sock.setblocking(False)

        self.username = None
        self.password = None
        self.realm = None
        self.nonce = None
        self.integrity_key = None
        self.relayed_addr = None
        self.software = None

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _gen_tid():
        return bytes([random.randint(0, 255) for _ in range(12)])

    @staticmethod
    def _build_attr(attr_type, value):
        pad_len = (4 - len(value) % 4) % 4
        return struct.pack('!HH', attr_type, len(value)) + value + b'\x00' * pad_len

    def _build_xor_addr(self, attr_type, ip_str, port, tid):
        family = 0x01 if ':' not in ip_str else 0x02
        data = struct.pack('!H', family)
        data += struct.pack('!H', port ^ (STUN_MAGIC_COOKIE >> 16))
        if family == 0x01:
            ip_int = struct.unpack('!I', socket.inet_aton(ip_str))[0] ^ STUN_MAGIC_COOKIE
            data += struct.pack('!I', ip_int)
        else:
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip_str)
            mask = struct.pack('!I', STUN_MAGIC_COOKIE) + tid
            data += bytes([ip_bytes[i] ^ mask[i] for i in range(16)])
        return self._build_attr(attr_type, data)

    @staticmethod
    def _parse_xor_addr_value(value, tid):
        if len(value) < 4:
            return None
        family = struct.unpack('!H', value[0:2])[0]
        port = struct.unpack('!H', value[2:4])[0] ^ (STUN_MAGIC_COOKIE >> 16)
        if family == 0x01:
            if len(value) < 8:
                return None
            ip_int = struct.unpack('!I', value[4:8])[0] ^ STUN_MAGIC_COOKIE
            ip = socket.inet_ntoa(struct.pack('!I', ip_int))
            return (ip, port)
        elif family == 0x02:
            if len(value) < 20:
                return None
            mask = struct.pack('!I', STUN_MAGIC_COOKIE) + tid
            ip_b = bytes([value[4 + i] ^ mask[i] for i in range(16)])
            ip = socket.inet_ntop(socket.AF_INET6, ip_b)
            return (ip, port)
        return None

    @staticmethod
    def _parse_mapped_addr(value):
        if len(value) < 4:
            return None
        family = struct.unpack('!H', value[0:2])[0]
        port = struct.unpack('!H', value[2:4])[0]
        if family == 0x01:
            if len(value) < 8:
                return None
            ip = socket.inet_ntoa(value[4:8])
            return (ip, port)
        elif family == 0x02:
            if len(value) < 20:
                return None
            ip = socket.inet_ntop(socket.AF_INET6, value[4:20])
            return (ip, port)
        return None

    @staticmethod
    def _parse_attrs(data, offset):
        attrs = {}
        while offset + 4 <= len(data):
            t, l = struct.unpack('!HH', data[offset:offset + 4])
            v = data[offset + 4:offset + 4 + l]
            pad = (4 - l % 4) % 4
            offset += 4 + l + pad
            attrs[t] = v
        return attrs

    @staticmethod
    def _parse_error(value):
        if len(value) < 4:
            return "Unknown error"
        code = (value[2] & 0x07) * 100 + (value[3] & 0xFF)
        reason = value[4:].decode('utf-8', errors='ignore')
        return f"{code} {reason}"

    def _build_msg(self, msg_type, tid, attrs_list, with_integrity=False):
        attrs_bytes = b''.join(attrs_list)
        if with_integrity:
            body_len = len(attrs_bytes) + 24  # MESSAGE-INTEGRITY: 4 header + 20 HMAC
            header = struct.pack('!HHI', msg_type, body_len, STUN_MAGIC_COOKIE) + tid
            msg = header + attrs_bytes
            mi = hmac.new(self.integrity_key, msg, hashlib.sha1).digest()
            return msg + self._build_attr(ATTR_MESSAGE_INTEGRITY, mi)
        else:
            body_len = len(attrs_bytes)
            header = struct.pack('!HHI', msg_type, body_len, STUN_MAGIC_COOKIE) + tid
            return header + attrs_bytes

    def _send_recv(self, msg, expected_tid, timeout=5):
        self.sock.sendto(msg, self.server_addr)
        start = time.time()
        while time.time() - start < timeout:
            ready, _, _ = select.select([self.sock], [], [], timeout - (time.time() - start))
            if not ready:
                break
            data, addr = self.sock.recvfrom(2048)
            if len(data) < 20:
                continue
            msg_type, body_len, cookie, tid = struct.unpack('!HHI12s', data[:20])
            if cookie != STUN_MAGIC_COOKIE:
                continue
            if tid != expected_tid:
                continue
            return data, addr
        raise TimeoutError("No matching STUN response received")

    # ------------------------------------------------------------------
    # STUN Binding Test
    # ------------------------------------------------------------------
    def stun_bind(self):
        tid = self._gen_tid()
        msg = self._build_msg(MSG_BINDING_REQUEST, tid, [], with_integrity=False)
        data, addr = self._send_recv(msg, tid)
        msg_type, _, _, resp_tid = struct.unpack('!HHI12s', data[:20])
        if msg_type != MSG_BINDING_RESPONSE:
            raise Exception(f"Unexpected STUN response type: 0x{msg_type:04x}")
        attrs = self._parse_attrs(data, 20)
        self.software = attrs.get(ATTR_SOFTWARE, b'').decode('utf-8', errors='ignore') or None
        if ATTR_XOR_MAPPED_ADDRESS in attrs:
            return self._parse_xor_addr_value(attrs[ATTR_XOR_MAPPED_ADDRESS], resp_tid)
        elif ATTR_MAPPED_ADDRESS in attrs:
            return self._parse_mapped_addr(attrs[ATTR_MAPPED_ADDRESS])
        else:
            raise Exception("Binding response missing mapped address")

    # ------------------------------------------------------------------
    # TURN Allocate
    # ------------------------------------------------------------------
    def turn_allocate(self, username, password):
        self.username = username
        self.password = password

        tid = self._gen_tid()
        attrs = [self._build_attr(ATTR_REQUESTED_TRANSPORT, b'\x11\x00\x00\x00')]
        msg = self._build_msg(MSG_ALLOCATE_REQUEST, tid, attrs, with_integrity=False)
        data, addr = self._send_recv(msg, tid)

        msg_type, _, _, resp_tid = struct.unpack('!HHI12s', data[:20])
        resp_attrs = self._parse_attrs(data, 20)

        if msg_type == MSG_ALLOCATE_RESPONSE:
            # Server does not require authentication (no-auth)
            self.software = resp_attrs.get(ATTR_SOFTWARE, b'').decode('utf-8', errors='ignore') or None
            if ATTR_XOR_RELAYED_ADDRESS in resp_attrs:
                self.relayed_addr = self._parse_xor_addr_value(
                    resp_attrs[ATTR_XOR_RELAYED_ADDRESS], resp_tid)
                return self.relayed_addr
            raise Exception("Allocate success but no XOR-RELAYED-ADDRESS")

        # Handle 401 Challenge
        if msg_type & 0x0110 == 0x0110:
            if ATTR_REALM not in resp_attrs or ATTR_NONCE not in resp_attrs:
                raise Exception(f"Allocate rejected without realm/nonce: {self._parse_error(resp_attrs.get(ATTR_ERROR_CODE, b''))}")
            self.realm = resp_attrs[ATTR_REALM].decode('utf-8')
            self.nonce = resp_attrs[ATTR_NONCE]
            self.integrity_key = hashlib.md5(
                f"{self.username}:{self.realm}:{self.password}".encode()).digest()

            # Resend Allocate Request with authentication
            tid = self._gen_tid()
            attrs = [
                self._build_attr(ATTR_REQUESTED_TRANSPORT, b'\x11\x00\x00\x00'),
                self._build_attr(ATTR_USERNAME, self.username.encode('utf-8')),
                self._build_attr(ATTR_REALM, self.realm.encode('utf-8')),
                self._build_attr(ATTR_NONCE, self.nonce),
            ]
            msg = self._build_msg(MSG_ALLOCATE_REQUEST, tid, attrs, with_integrity=True)
            data, addr = self._send_recv(msg, tid)

            msg_type2, _, _, resp_tid2 = struct.unpack('!HHI12s', data[:20])
            resp_attrs2 = self._parse_attrs(data, 20)
            if msg_type2 == MSG_ALLOCATE_RESPONSE:
                self.software = resp_attrs2.get(ATTR_SOFTWARE, b'').decode('utf-8', errors='ignore') or None
                if ATTR_XOR_RELAYED_ADDRESS in resp_attrs2:
                    self.relayed_addr = self._parse_xor_addr_value(
                        resp_attrs2[ATTR_XOR_RELAYED_ADDRESS], resp_tid2)
                    return self.relayed_addr
                raise Exception("Authenticated allocate success but no XOR-RELAYED-ADDRESS")
            else:
                raise Exception(f"Authenticated allocate failed: {self._parse_error(resp_attrs2.get(ATTR_ERROR_CODE, b''))}")

        raise Exception(f"Unexpected allocate response type: 0x{msg_type:04x}")

    # ------------------------------------------------------------------
    # TURN CreatePermission
    # ------------------------------------------------------------------
    def turn_create_permission(self, peer_ip, peer_port):
        if not self.integrity_key:
            raise Exception("Must allocate first to obtain credentials")
        tid = self._gen_tid()
        attrs = [
            self._build_xor_addr(ATTR_XOR_PEER_ADDRESS, peer_ip, peer_port, tid),
            self._build_attr(ATTR_USERNAME, self.username.encode('utf-8')),
            self._build_attr(ATTR_REALM, self.realm.encode('utf-8')),
            self._build_attr(ATTR_NONCE, self.nonce),
        ]
        msg = self._build_msg(MSG_CREATE_PERMISSION_REQUEST, tid, attrs, with_integrity=True)
        data, addr = self._send_recv(msg, tid)
        msg_type, _, _, _ = struct.unpack('!HHI12s', data[:20])
        if msg_type == MSG_CREATE_PERMISSION_RESPONSE:
            return True
        resp_attrs = self._parse_attrs(data, 20)
        raise Exception(f"CreatePermission failed: {self._parse_error(resp_attrs.get(ATTR_ERROR_CODE, b''))}")

    # ------------------------------------------------------------------
    # TURN Send / Recv (Indication)
    # ------------------------------------------------------------------
    def turn_send(self, peer_ip, peer_port, payload):
        tid = self._gen_tid()
        attrs = [
            self._build_xor_addr(ATTR_XOR_PEER_ADDRESS, peer_ip, peer_port, tid),
            self._build_attr(ATTR_DATA, payload),
        ]
        msg = self._build_msg(MSG_SEND_INDICATION, tid, attrs, with_integrity=False)
        self.sock.sendto(msg, self.server_addr)

    def turn_recv(self, timeout=5):
        start = time.time()
        while time.time() - start < timeout:
            remaining = timeout - (time.time() - start)
            ready, _, _ = select.select([self.sock], [], [], max(0, remaining))
            if not ready:
                return None, None
            data, addr = self.sock.recvfrom(2048)
            if len(data) < 20:
                continue
            msg_type, _, cookie, tid = struct.unpack('!HHI12s', data[:20])
            if cookie != STUN_MAGIC_COOKIE or msg_type != MSG_DATA_INDICATION:
                continue
            attrs = self._parse_attrs(data, 20)
            if ATTR_XOR_PEER_ADDRESS in attrs and ATTR_DATA in attrs:
                peer = self._parse_xor_addr_value(attrs[ATTR_XOR_PEER_ADDRESS], tid)
                return attrs[ATTR_DATA], peer
        return None, None

    def close(self):
        self.sock.close()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Pure Python STUN / TURN test script by miuda.ai")
    parser.add_argument("-stun", help="STUN server address, e.g. 124.223.96.208:3478")
    parser.add_argument("-turn", help="TURN server address, e.g. 124.223.96.208:3478")
    parser.add_argument("-u", "--username", help="TURN username")
    parser.add_argument("-p", "--password", help="TURN password")
    args = parser.parse_args()

    if not args.stun and not args.turn:
        parser.print_help()
        sys.exit(1)

    def print_server_info(label, addr_str, software):
        host, port = addr_str.rsplit(':', 1)
        log(f"{label} server address: {addr_str}")
        log(f"{label} server IP: {host}")
        if software:
            log(f"{label} server software: {software}")
        else:
            log(f"{label} server software: (unknown)")

    # 1. STUN test
    if args.stun:
        stun_addr = parse_addr(args.stun)
        log("=== 1. STUN Binding Test ===")
        client = StunTurnClient(stun_addr)
        try:
            mapped = client.stun_bind()
            print_server_info("STUN", args.stun, client.software)
            log(f"[OK] STUN mapped address: {mapped[0]}:{mapped[1]}")
        except Exception as e:
            log(f"[FAIL] STUN test failed: {e}")
        finally:
            client.close()

    # 2. TURN test
    if args.turn and args.username and args.password:
        turn_addr = parse_addr(args.turn)
        username = args.username
        password = args.password

        log("\n=== 2. TURN Allocate & Relay Test ===")
        client1 = StunTurnClient(turn_addr)
        client2 = StunTurnClient(turn_addr)
        try:
            relay1 = client1.turn_allocate(username, password)
            print_server_info("TURN", args.turn, client1.software)
            log(f"[OK] Client1 relayed address: {relay1[0]}:{relay1[1]}")

            relay2 = client2.turn_allocate(username, password)
            log(f"[OK] Client2 relayed address: {relay2[0]}:{relay2[1]}")

            # Create permissions for each other
            client1.turn_create_permission(relay2[0], relay2[1])
            log(f"[OK] Client1 created permission for {relay2[0]}:{relay2[1]}")

            client2.turn_create_permission(relay1[0], relay1[1])
            log(f"[OK] Client2 created permission for {relay1[0]}:{relay1[1]}")

            # Client1 -> Client2
            msg1 = b"Hello from TURN client1"
            client1.turn_send(relay2[0], relay2[1], msg1)
            log(f"[->] Client1 sent: {msg1!r}")

            data, from_addr = client2.turn_recv(timeout=5)
            if data:
                log(f"[<-] Client2 received: {data!r} from {from_addr}")
            else:
                log("[FAIL] Client2 receive timeout")

            # Client2 -> Client1
            msg2 = b"Hello from TURN client2"
            client2.turn_send(relay1[0], relay1[1], msg2)
            log(f"[->] Client2 sent: {msg2!r}")

            data2, from_addr2 = client1.turn_recv(timeout=5)
            if data2:
                log(f"[<-] Client1 received: {data2!r} from {from_addr2}")
            else:
                log("[FAIL] Client1 receive timeout")

        except Exception as e:
            log(f"[FAIL] TURN test failed: {e}")
        finally:
            client1.close()
            client2.close()
    elif args.turn or args.username or args.password:
        log("[SKIP] TURN test skipped: -turn, -u and -p must all be provided together")


if __name__ == '__main__':
    main()
