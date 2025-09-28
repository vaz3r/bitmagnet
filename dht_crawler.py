# DHT Crawler in Python
# This script will crawl the BitTorrent DHT to find torrents and save the results to a JSON file.

import socket
import json
import hashlib
import random
import time
import threading
import os
import struct
from bencode2 import bencode, bdecode

class MetadataFetcher:
    def __init__(self, info_hash, peers, timeout=5):
        self.info_hash = info_hash
        self.peers = peers
        self.timeout = timeout
        self.metadata = None

    def fetch(self):
        for peer_addr in self.peers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    ip, port = peer_addr.split(":")
                    s.settimeout(self.timeout)
                    s.connect((ip, int(port)))

                    # Handshake
                    handshake = struct.pack('>B19s8x20s20s', 19, b'BitTorrent protocol', self.info_hash, self.info_hash) # Using info_hash as peer_id for simplicity
                    s.sendall(handshake)

                    response_handshake = s.recv(68)
                    if len(response_handshake) < 68:
                        continue

                    # Unpack response
                    pstrlen, protocol, reserved, info_hash_resp, peer_id_resp = struct.unpack('>B19s8s20s20s', response_handshake)

                    if info_hash_resp != self.info_hash:
                        continue

                    # Extended handshake (BEP-0010)
                    extended_handshake_message = b'\x14\x00' + bencode({b'm': {b'ut_metadata': 1}})
                    s.sendall(struct.pack('>I', len(extended_handshake_message)) + extended_handshake_message)

                    # Receive and process messages
                    metadata_pieces = {}
                    ut_metadata_id = None
                    metadata_size = None

                    while True:
                        msg_len_data = s.recv(4)
                        if not msg_len_data: break
                        msg_len = struct.unpack('>I', msg_len_data)[0]
                        if msg_len == 0: continue # keep-alive

                        msg_data = s.recv(msg_len)
                        if not msg_data: break

                        msg_id = msg_data[0]

                        if msg_id == 20: # Extended message
                            extended_msg_id = msg_data[1]
                            payload = bdecode(msg_data[2:])

                            if extended_msg_id == 0: # Handshake
                                ut_metadata_id = payload[b'm'][b'ut_metadata']
                                metadata_size = payload[b'metadata_size']

                                # Request metadata pieces
                                for i in range((metadata_size + 16383) // 16384):
                                    request = {b'msg_type': 0, b'piece': i}
                                    request_msg = b'\x14' + bytes([ut_metadata_id]) + bencode(request)
                                    s.sendall(struct.pack('>I', len(request_msg)) + request_msg)

                            elif extended_msg_id == ut_metadata_id:
                                # This is where the metadata piece is attached
                                piece_index_start = msg_data.find(b'ee') + 2
                                metadata_piece = msg_data[piece_index_start:]
                                piece_index = payload[b'piece']
                                metadata_pieces[piece_index] = metadata_piece

                                if len(metadata_pieces) * 16384 >= metadata_size:
                                    # We have all the pieces
                                    full_metadata = b"".join(metadata_pieces[i] for i in sorted(metadata_pieces.keys()))

                                    # Verify metadata
                                    if hashlib.sha1(full_metadata).digest() == self.info_hash:
                                        self.metadata = bdecode(full_metadata)
                                        return self.metadata # Success
                                    else:
                                        break # Checksum failed, try next peer
                        if self.metadata:
                            break
            except (socket.timeout, ConnectionRefusedError, OSError, struct.error, IndexError) as e:
                # Common network errors, trying next peer
                continue
            except Exception as e:
                print(f"Failed to fetch metadata from {peer_addr}: {e}")
        return self.metadata

class DHTCrawler:
    def __init__(self, bootstrap_nodes=[("router.bittorrent.com", 6881), ("dht.transmissionbt.com", 6881), ("router.utorrent.com", 6881)]):
        self.bootstrap_nodes = bootstrap_nodes
        self.node_id = self.generate_node_id()
        self.routing_table = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind(("0.0.0.0", 6881)) # Listen on the default DHT port
        except OSError as e:
            print(f"Error binding to socket: {e}. Port 6881 might be in use.")
            raise
        self.torrents = {}

    def generate_node_id(self):
        return hashlib.sha1(str(random.randint(0, 2**160)).encode()).digest()

    def generate_transaction_id(self):
        return os.urandom(2)

    def distance(self, node_id1, node_id2):
        return int.from_bytes(node_id1, 'big') ^ int.from_bytes(node_id2, 'big')

    def start(self):
        print("Starting DHT Crawler...")
        self.bootstrap()
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.daemon = True
        listen_thread.start()
        crawl_thread = threading.Thread(target=self.crawl)
        crawl_thread.daemon = True
        crawl_thread.start()

        while True:
            time.sleep(60)
            self.save_torrents()

    def bootstrap(self):
        for node in self.bootstrap_nodes:
            print(f"Bootstrapping from {node}...")
            self.send_find_node(node)

    def listen(self):
        print("Listening for DHT messages...")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                message = bdecode(data)
                self.handle_message(message, addr)
            except Exception as e:
                print(f"Error in listen: {e}")

    def crawl(self):
        while True:
            if not self.routing_table:
                # Wait for the initial bootstrap to populate the table
                time.sleep(5)
                continue

            for node_id, ip, port in self.routing_table[:]:
                self.send_find_node((ip, port), target=self.generate_node_id())
            time.sleep(1)

    def handle_message(self, message, addr):
        msg_type = message.get(b"y", b"").decode()
        if msg_type == "r":
            if b"nodes" in message.get(b"r", {}):
                self.handle_find_node_response(message)
        elif msg_type == "q":
            query_type = message.get(b"q", b"").decode()
            if query_type == "get_peers":
                self.handle_get_peers_query(message, addr)
            elif query_type == "ping":
                self.handle_ping_query(message, addr)
            elif query_type == "find_node":
                self.handle_find_node_query(message, addr)
            elif query_type == "announce_peer":
                 self.handle_announce_peer_query(message, addr)


    def handle_find_node_response(self, message):
        nodes = message.get(b"r", {}).get(b"nodes", b"")
        for i in range(0, len(nodes), 26):
            node_id = nodes[i:i+20]
            ip = socket.inet_ntoa(nodes[i+20:i+24])
            port = int.from_bytes(nodes[i+24:i+26], 'big')
            # A simple routing table. We check for node ID existence to avoid duplicates.
            if not any(n[0] == node_id for n in self.routing_table):
                if len(self.routing_table) < 200:
                    self.routing_table.append((node_id, ip, port))


    def handle_get_peers_query(self, message, addr):
        info_hash = message[b"a"][b"info_hash"]
        info_hash_hex = info_hash.hex()
        if info_hash_hex not in self.torrents:
            print(f"Discovered new infohash: {info_hash_hex}")
            self.torrents[info_hash_hex] = {"sources": [], "metadata": None}
            # Start metadata fetching in a new thread
            fetcher = MetadataFetcher(info_hash, [f"{addr[0]}:{addr[1]}"])
            thread = threading.Thread(target=self.fetch_and_store_metadata, args=(fetcher, info_hash_hex))
            thread.daemon = True
            thread.start()

        source_addr = f"{addr[0]}:{addr[1]}"
        if source_addr not in self.torrents[info_hash_hex]["sources"]:
            self.torrents[info_hash_hex]["sources"].append(source_addr)

        # Respond to the get_peers query
        # For simplicity, we won't implement a full peer response yet
        # We will respond with a dummy message to keep the connection alive
        token = info_hash[:2]
        response = {
            b"t": message[b"t"],
            b"y": b"r",
            b"r": {
                b"id": self.generate_node_id(),
                b"token": token,
                b"nodes": b""
            }
        }
        self.send_message(response, addr)


    def handle_announce_peer_query(self, message, addr):
        info_hash = message[b"a"][b"info_hash"]
        info_hash_hex = info_hash.hex()
        if info_hash_hex not in self.torrents:
            print(f"Discovered new infohash from announce_peer: {info_hash_hex}")
            self.torrents[info_hash_hex] = {"sources": [], "metadata": None}
            # Start metadata fetching in a new thread
            fetcher = MetadataFetcher(info_hash, [f"{addr[0]}:{addr[1]}"])
            thread = threading.Thread(target=self.fetch_and_store_metadata, args=(fetcher, info_hash_hex))
            thread.daemon = True
            thread.start()

        source_addr = f"{addr[0]}:{addr[1]}"
        if source_addr not in self.torrents[info_hash_hex]["sources"]:
            self.torrents[info_hash_hex]["sources"].append(source_addr)

        # Acknowledge the announce_peer query
        response = {
            b"t": message[b"t"],
            b"y": b"r",
            b"r": {
                b"id": self.node_id
            }
        }
        self.send_message(response, addr)

    def fetch_and_store_metadata(self, fetcher, info_hash_hex):
        metadata = fetcher.fetch()
        if metadata:
            # Basic sanitization for JSON output
            def sanitize(data):
                if isinstance(data, bytes):
                    return data.decode('utf-8', 'ignore')
                if isinstance(data, list):
                    return [sanitize(item) for item in data]
                if isinstance(data, dict):
                    return {sanitize(key): sanitize(value) for key, value in data.items()}
                return data

            self.torrents[info_hash_hex]["metadata"] = sanitize(metadata)
            print(f"Successfully fetched metadata for {info_hash_hex}")

    def handle_ping_query(self, message, addr):
        response = {
            b"t": message[b"t"],
            b"y": b"r",
            b"r": {
                b"id": self.node_id
            }
        }
        self.send_message(response, addr)

    def handle_find_node_query(self, message, addr):
        target_id = message[b"a"][b"target"]

        # Sort nodes by distance to the target
        self.routing_table.sort(key=lambda node: self.distance(node[0], target_id))

        # Get the K closest nodes (K=8)
        closest_nodes = self.routing_table[:8]

        # Compact node info
        nodes_compact = b"".join([
            node_id + socket.inet_aton(ip) + port.to_bytes(2, 'big')
            for node_id, ip, port in closest_nodes
        ])

        response = {
            b"t": message[b"t"],
            b"y": b"r",
            b"r": {
                b"id": self.node_id,
                b"nodes": nodes_compact
            }
        }
        self.send_message(response, addr)

    def send_find_node(self, addr, target=None):
        if target is None:
            target = self.node_id

        message = {
            b"t": self.generate_transaction_id(),
            b"y": b"q",
            b"q": b"find_node",
            b"a": {
                b"id": self.node_id,
                b"target": target
            }
        }
        self.send_message(message, addr)

    def send_message(self, message, addr):
        try:
            self.sock.sendto(bencode(message), addr)
        except Exception as e:
            print(f"Error sending message to {addr}: {e}")

    def save_torrents(self):
        print("Saving torrents to torrents.json...")
        with open("torrents.json", "w") as f:
            json.dump(self.torrents, f, indent=4)

if __name__ == "__main__":
    crawler = DHTCrawler()
    crawler.start()