import socket
import threading
from cryptography.fernet import Fernet, InvalidToken
from security.crypto import CryptoHandler
from security.protocol import PacketType, ProtocolHandler
from security.rsa_utils import RSAUtils

HANDSHAKE_TIMEOUT = 5 # Seconds before a pending peer is dropped
_AddressMap = dict[int, str]  # id(socket) -> address string

class P2PNode:
    def __init__(
        self,
        host: str,
        port: int,
        username: str = "Anonymous",
        on_message=None,
        on_disconnect=None,
        on_connected=None
    ) -> None:
        self.host = host
        self.port = port
        self.username = username

        self.on_message = on_message
        self.on_disconnect = on_disconnect
        self.on_connected = on_connected

        self.server_socket: socket.socket | None = None

        # All three dicts are protected by peers_lock.
        self.peers_lock = threading.RLock()
        self.peers: dict[str, socket.socket] = {}
        self.peer_sessions: dict[str, dict] = {}

        # This reverse mapping is used to find the peer address when we only have the socket (e.g. on disconnect).
        self._sock_to_addr: _AddressMap = {}

        #self.crypto_handler = CryptoHandler()
        self.protocol_handler = ProtocolHandler()

        # RSA key pair — used only for session-key exchange.
        self.private_key, self.public_key = (RSAUtils.generate_key_pair())

        self.seen_messages = set()
        self.receive_threads = []

        self.is_running = False

    def start_server(self) -> None:
        """Start the TCP server."""

        self.server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.server_socket.settimeout(1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.is_running = True

        print(f"[INFO] Listening on {self.host}:{self.port}")
        
        threading.Thread(
            target=self.accept_connections,
            daemon=True,
            name="AcceptThread"
        ).start()

    def stop_server(self) -> None:
        """Stop the TCP server and close all connections."""
        self.is_running = False

        with self.peers_lock:

            for sock in self.peers.values():

                try:
                    sock.close()

                except OSError:
                    pass

            self.peers.clear()
            self.peer_sessions.clear()
            self._sock_to_addr.clear()

        if self.server_socket is not None:

            try:
                self.server_socket.close()

            except OSError:
                pass

            print("[INFO] Server stopped.")

        for thread in self.receive_threads:
            thread.join(timeout=1)
        
        self.receive_threads.clear()

    # Connection lifecycle
    def accept_connections(self) -> None:
        """Accept incoming peer connections (runs on its own thread)."""
        if self.server_socket is None:
            return

        while self.is_running:
            try:
                client_socket, address = self.server_socket.accept()
                peer_address = f"{address[0]}:{address[1]}"

                print(f"[INFO] Incoming connection from {peer_address}")

                if not self.register_peer(peer_address, client_socket, is_initiator=False):
                    print(f"[INFO] Already connected: {peer_address}")
                    client_socket.close()
                    continue

                self.start_receive_thread(peer_address, client_socket)
                self.schedule_handshake_timeout(peer_address)

            except socket.timeout:
                continue

            except OSError:
                if self.is_running:
                    print("[ERROR] Accept connection failed")
                break

    # Networking interface
    # Used by GUI layer
    def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to another peer and initiate the handshake."""
        peer_address = f"{host}:{port}"

        with self.peers_lock:
            if peer_address in self.peers:
                print(f"[INFO] Already connected to {peer_address}")
                return False

        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.settimeout(10)
            peer_socket.connect((host, port))
            peer_socket.settimeout(None)

            print(f"[INFO] Connected to {peer_address}")

            if not self.register_peer(peer_address, peer_socket, is_initiator=True):
                print(f"[INFO] Already connected to {peer_address}")
                peer_socket.close()
                return False

            if not self.send_handshake(peer_socket):
                self.remove_peer(peer_socket)
                return False

            self.start_receive_thread(peer_address, peer_socket)
            self.schedule_handshake_timeout(peer_address)

            return True

        except OSError as error:
            print(f"[ERROR] Failed to connect to {peer_address}: {error}")
            return False  

    # Message sending and receiving
    def send_message(self, message: str, peer_address: str) -> bool:
        """Send a message to a connected peer."""

        with self.peers_lock:
            session = self.peer_sessions.get(peer_address)
            peer_socket = self.peers.get(peer_address)

        if session is None or session["state"] != "active":
            print(f"[WARNING] Peer not ready: {peer_address}")
            return False

        if peer_socket is None:
            return False

        crypto: CryptoHandler | None = session.get("crypto")
        
        retry = 3

        for attempt in range(retry):

            try:
                packet = self.protocol_handler.create_packet(
                   PacketType.MESSAGE,
                   self.username,
                   message,
                   crypto=crypto,
                )
                peer_socket.sendall(
                    self.protocol_handler.serialize(packet)
                )
                return True

            except (BrokenPipeError, OSError) as error:

                print(f"[WARNING] Send failed "
                      f"({attempt + 1}/{retry}) "
                      f"to {peer_address}: {error}"
                )
        self.remove_peer(peer_socket)
        return False

    def receive_messages(self, peer_socket: socket.socket) -> None:
        """Receive loop — dispatches to handlers. Must never raise."""
        while self.is_running:

            try:
                packet = self.protocol_handler.receive_packet(peer_socket)

                if packet is None:
                    self.remove_peer(peer_socket)
                    break

                if not isinstance(packet, dict):
                    print("[WARNING] Non-dict packet received — dropping")
                    continue

                msg_type = packet.get("type", "")

                if msg_type == PacketType.HANDSHAKE:
                    self.handle_handshake(packet, peer_socket)

                elif msg_type == PacketType.HANDSHAKE_ACK:
                    self.handle_handshake_ack(packet, peer_socket)

                elif msg_type == PacketType.SESSION_KEY:
                    self.handle_session_key(packet, peer_socket)

                elif msg_type == PacketType.MESSAGE:
                    self.handle_message(packet, peer_socket)

                else:
                    print(f"[WARNING] Unknown packet type '{msg_type}' — dropping")

            except (ConnectionResetError, BrokenPipeError):
                print("[INFO] Connection reset by peer")
                self.remove_peer(peer_socket)
                break

            except (OSError, ValueError, KeyError, InvalidToken) as error:
                if self.is_running:
                    print(f"[ERROR] Receive error: {error}")
                self.remove_peer(peer_socket)
                break

    def broadcast_message(self, message: str) -> tuple[int, int]:
        """Send *message* to every active peer."""

        with self.peers_lock:
            active = [
                addr
                for addr, session in self.peer_sessions.items()
                if session["state"] == "active"
            ]

        sent = 0
        failed = 0

        counter_lock = threading.lock()
        threads = []

        def send_to_peer(peer_address):

            nonlocal sent, failed

            success =  self.send_message(message, peer_address)
            with counter_lock:
                if success:
                    sent += 1
                else:
                    failed += 1

        for peer_address in active:
            thread = threading.Thread(
                target=send_to_peer,
                args=(peer_address,)
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        self.cleanup_dead_peers()
        return sent, failed
    
    # Internal handlers
    def handle_handshake(self, packet: dict, peer_socket: socket.socket) -> None:
        
        if not self.protocol_handler.validate_packet(packet):
            print("[WARNING] Malformed handshake — disconnecting peer")
            self.remove_peer(peer_socket)
            return

        peer_address = self.get_peer_address(peer_socket)

        if peer_address is None:
            return

        real_peer_address = (
            f"{peer_address.split(':')[0]}:"
            f"{packet['listen_port']}"
        )

        with self.peers_lock:

            if (
                real_peer_address != peer_address
                and real_peer_address in self.peers
            ):
                print(
                    f"[INFO] Duplicate connection detected: "
                    f"{peer_address} -> {real_peer_address}"
                )

                self.remove_peer(peer_socket)
                return

        print(f"[HANDSHAKE] Received from {peer_address} (user: {packet['username']})")

        # Validate the public key before proceeding with the handshake.
        try:
            RSAUtils.load_public_key(packet["public_key"])

        except Exception:
            print("[WARNING] Invalid public key")
            self.remove_peer(peer_socket)
            return
        
        with self.peers_lock:
            session = self.peer_sessions.get(peer_address)

            if session is None:
                return
    
            session["public_key"] = packet["public_key"]
            session["username"] = packet.get("username", "Unknown")
            session["listen_port"] = packet.get("listen_port")

        ack = {
            "type": PacketType.HANDSHAKE_ACK,
            "status": "ok",
            "public_key": RSAUtils.serialize_public_key(self.public_key),
        }

        try:
            peer_socket.sendall(self.protocol_handler.serialize(ack))

        except OSError as error:
            print(f"[ERROR] Failed to send handshake_ack: {error}")
            self.remove_peer(peer_socket)
            return

    def handle_handshake_ack(self, packet: dict, peer_socket: socket.socket) -> None:
        
        if not self.protocol_handler.validate_packet(packet):
            print("[WARNING] Malformed handshake_ack — disconnecting peer")
            self.remove_peer(peer_socket)
            return
        
        peer_address = self.get_peer_address(peer_socket)

        if peer_address is None:
            return

        if packet.get("status") != "ok":
            print(f"[WARNING] Handshake_ack rejected by {peer_address}")
            self.remove_peer(peer_socket)
            return

        raw_key = packet.get("public_key", "")

        try:
            RSAUtils.load_public_key(raw_key)

        except Exception:
            print("[WARNING] Invalid RSA public key in handshake_ack — disconnecting")
            self.remove_peer(peer_socket)
            return

        is_initiator = False

        with self.peers_lock:
            session = self.peer_sessions.get(peer_address)
            if session is None:
                return
            
            session["public_key"] = raw_key
            is_initiator = session["is_initiator"]

        if is_initiator:
            self._send_session_key(peer_socket, peer_address)

    def handle_session_key(self, packet: dict, peer_socket: socket.socket) -> None:
        """Process the session key sent by the peer.  This is called by the 
        protocol handler after receiving a session_key packet."""

        peer_address = self.get_peer_address(peer_socket)

        if peer_address is None:
            return
        
        if not self.protocol_handler.validate_packet(packet):
            print(f"[WARNING] Invalid session_key packet from {peer_address}")
            self.remove_peer(peer_socket)
            return

        encrypted_key_hex = packet.get("payload", "")

        if not encrypted_key_hex:
            print(f"[WARNING] Empty session_key payload from {peer_address}")
            self.remove_peer(peer_socket)
            return

        try:
            encrypted_key = bytes.fromhex(encrypted_key_hex)
            fernet_key = RSAUtils.decrypt(self.private_key, encrypted_key)
            crypto = CryptoHandler(key=fernet_key)

        except Exception as exc:
            print(f"[WARNING] Failed to decrypt session key from {peer_address}: {exc}")
            self.remove_peer(peer_socket)
            return

        with self.peers_lock:
            session = self.peer_sessions.get(peer_address)

            if session is None:
                return
            
            session["crypto"] = crypto
            session["state"] = "active"
            count = len(self.peers)

        print(f"[INFO] Session key received — peer active: {peer_address} (peers: {count})")

        self._fire_callback(self.on_connected, peer_address)

    def handle_message(self, packet: dict, peer_socket: socket.socket) -> None:
        
        peer_address = self.get_peer_address(peer_socket)

        if peer_address is None:
            return
        
        with self.peers_lock:
            session = self.peer_sessions.get(peer_address)
        
        if session is None:
            return

        if session["state"] != "active":
            print(
            f"[WARNING] Message from non-active peer {peer_address}"
        )
            return

        if not self.protocol_handler.validate_packet(packet):
            print(f"[WARNING] Invalid message packet from {peer_address} — dropping")
            return
        
        message_id = packet["message_id"]
        with self.peers_lock:

            if message_id in self.seen_messages:
                print("[WARNING] Replay packet dropped")
                return
            
            self.seen_messages.add(message_id)

            if len(self.seen_messages) > 5000:
                self.seen_messages.clear()

        crypto: CryptoHandler | None = session.get("crypto")

        try:
            payload = self.protocol_handler.decrypt_payload(packet, crypto=crypto)

        except (InvalidToken, ValueError) as error:
            print(f"[WARNING] Decryption failed from {peer_address}: {error}")
            return

        sender = packet.get("sender", "Unknown")
        self._fire_callback(self.on_message, sender, payload)
    
    # Utility methods
    def get_peer_address(self, peer_socket: socket.socket) -> str | None:
        """O(1) reverse lookup: socket → address string."""

        with self.peers_lock:
            return self._sock_to_addr.get(id(peer_socket))

    def register_peer(self, peer_address: str, sock: socket.socket, is_initiator: bool) -> bool:
        """Atomically register *peer_address*."""
        with self.peers_lock:

            if peer_address in self.peers:
                return False
            
            self.peers[peer_address] = sock
            self._sock_to_addr[id(sock)] = peer_address

            self.peer_sessions[peer_address] = {
                "state": "pending",
                "public_key": None,
                "session_key": None,
                "crypto": None,
                "username": None,
                "is_initiator": is_initiator
            }

            count = len(self.peers)

        print(f"[INFO] Peer registered: {peer_address} — active peers: {count}")
        return True

    def remove_peer(self, peer_socket: socket.socket) -> None:
       """Remove disconnected peers."""
       dead_peers = []
       with self.peers_lock:
           for peer_address, sock in self.peers.items():
               try:
                   sock.getpeername()
               except OSError:
                   print(
                       f"[INFO] Dead peer found: "
                       f"{peer_address}"
                   )
                   dead_peers.apend(sock)
       for sock in dead_peers:
               self.remove_peer(sock)

    def start_receive_thread(self, peer_address: str, sock: socket.socket) -> None:
        thread = threading.Thread(
            target=self.receive_messages,
            args=(sock,),
            daemon=True,
            name=f"Recv-{peer_address}",
        )

        thread.start()
        self.receive_threads.append(thread)

    def send_handshake(self, peer_socket: socket.socket) -> bool:

        handshake = {
            "type": PacketType.HANDSHAKE,
            "username": self.username,
            "version": "1.0",
            "listen_port": self.port,
            "public_key": RSAUtils.serialize_public_key(self.public_key),
        }

        try:
            peer_socket.sendall(self.protocol_handler.serialize(handshake))
            return True
        
        except (BrokenPipeError, OSError) as error:
            print(f"[ERROR] Failed to send handshake: {error}")
            return False   

    def schedule_handshake_timeout(self, peer_address: str) -> None:
        """Disconnect *peer_address* if still pending after the timeout."""
        def check_timeout() -> None:

            peer_socket = None

            with self.peers_lock:

                session = self.peer_sessions.get(peer_address)

                if session is None or session["state"] != "pending":
                    return
                
                peer_socket = self.peers.get(peer_address)
            
            if peer_socket is None:
                return

            print(f"[WARNING] Handshake timeout — disconnecting {peer_address}")
            self.remove_peer(peer_socket)

        timer = threading.Timer(HANDSHAKE_TIMEOUT, check_timeout)
        timer.daemon = True
        timer.start()

    def _send_session_key(self, peer_socket: socket.socket, peer_address: str) -> None:
        """Generate a session key, encrypt it with the peer's RSA public key, and send it."""

        with self.peers_lock:
            session = self.peer_sessions.get(peer_address)

            if session is None:
                return
            
            raw_peer_key = session.get("public_key")

        if not raw_peer_key:
            print(f"[WARNING] No peer public key for {peer_address} — cannot send session key")
            return

        try:
            peer_pub = RSAUtils.load_public_key(raw_peer_key)

        except Exception as exc:
            print(f"[ERROR] Cannot load peer public key for {peer_address}: {exc}")
            self.remove_peer(peer_socket)
            return

        # Generate a fresh Fernet key for this direction.
        fernet_key = Fernet.generate_key()
        try:
            encrypted_key = RSAUtils.encrypt(peer_pub, fernet_key)

        except Exception as exc:
            print(f"[ERROR] RSA encrypt failed for {peer_address}: {exc}")
            self.remove_peer(peer_socket)
            return

        session_key_packet = {
            "type": PacketType.SESSION_KEY,
            "payload": encrypted_key.hex(),
        }

        try:
            peer_socket.sendall(self.protocol_handler.serialize(session_key_packet))

        except (BrokenPipeError, OSError) as exc:
            print(f"[ERROR] Failed to send session key to {peer_address}: {exc}")
            self.remove_peer(peer_socket)
            return

        crypto = CryptoHandler(key=fernet_key)
        became_active = False

        with self.peers_lock:
            session = self.peer_sessions.get(peer_address)

            if session is not None:
                became_active = session.get("state") != "active"
                session["session_key"] = fernet_key
                session["crypto"] = crypto
                session["state"] = "active"

        print(f"[INFO] Session key sent to {peer_address}")
        if became_active:
            self._fire_callback(self.on_connected, peer_address)

    def _fire_callback(self, callback, *args) -> None:
        if callback is None:
            return
        try:
            callback(*args)
            
        except Exception as exc:
            print(f"[ERROR] Callback {callback.__name__} raised: {exc}")
