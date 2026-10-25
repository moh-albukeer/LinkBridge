"""
LinkBridge Node Controller (`bridge_node.py`).
Integrates:
- DeviceIdentity & Certificate Renewal / Revocation
- PairingManager & SessionManager (short-lived authenticated sessions, rejecting unauthenticated frames)
- ClipboardBridgeManager & FileTransferManager
- Wi-Fi TLS Server/Client listener and Bluetooth RFCOMM listener
"""
import socket
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from protocol.constants import DEFAULT_WIFI_PORT, MessageType, TransportType
from protocol.crypto import DeviceIdentity, PairingManager, SessionInfo, SessionManager
from protocol.messages import ProtocolFrame
from protocol.transport import (
    AuthenticationError,
    BluetoothRfcommTransport,
    TransportAdapter,
    TransportError,
    WifiTlsTransport,
)
from .clipboard_manager import ClipboardBridgeManager, SystemClipboardBackend
from .file_manager import FileTransferManager
from .storage import LocalStorage


class LinkBridgeNode:
    """
    Complete operational node representing either a Windows PC or an Android endpoint in Python tests/desktop runtime.
    """

    def __init__(
        self,
        data_dir: Path,
        device_name: str = "LinkBridge-Windows",
        platform: str = "Windows",
        on_event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        approval_prompt_callback: Optional[Callable[[Dict[str, Any]], bool]] = None,
        pairing_approval_callback: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.identity = DeviceIdentity.load_or_create(
            self.data_dir / "identity",
            device_name=device_name,
            platform=platform,
        )
        self.storage = LocalStorage(
            db_path=self.data_dir / "linkbridge.db",
            default_receive_dir=self.data_dir / "ReceivedFiles",
        )
        self.storage.set_setting("device_name", device_name)

        self.pairing_manager = PairingManager()
        self.session_manager = SessionManager()
        self.clipboard_backend = SystemClipboardBackend()
        self.on_event_callback = on_event_callback
        self.pairing_approval_callback = pairing_approval_callback

        self.clipboard_manager = ClipboardBridgeManager(
            local_device_id=self.identity.device_id,
            storage=self.storage,
            clipboard_backend=self.clipboard_backend,
            on_item_received_callback=lambda item: self._emit("CLIPBOARD_RECEIVED", item),
        )
        self.file_manager = FileTransferManager(
            local_device_id=self.identity.device_id,
            storage=self.storage,
            on_progress_callback=lambda prog: self._emit("FILE_PROGRESS", prog),
            approval_prompt_callback=approval_prompt_callback,
        )

        self.active_transport: Optional[TransportAdapter] = None
        self.active_pin: Optional[str] = None
        self.active_secret_hex: Optional[str] = None
        self._server_sock: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._listening = False
        self._op_lock = threading.Lock()

    def _emit(self, event_type: str, data: Dict[str, Any]) -> None:
        if self.on_event_callback:
            self.on_event_callback(event_type, data)

    def generate_pairing_code(self) -> Tuple[str, str, float]:
        """Generate a fresh 5-minute 6-digit PIN and 128-bit QR secret."""
        pin, secret_hex, exp = self.pairing_manager.generate_pairing_challenge()
        self.active_pin = pin
        self.active_secret_hex = secret_hex
        return pin, secret_hex, exp

    def renew_device_certificate(self) -> DeviceIdentity:
        """Renew local X.509 certificate and invalidate existing sessions."""
        self.session_manager.revoke_all()
        self.identity = DeviceIdentity.generate_new(
            self.data_dir / "identity",
            device_name=self.storage.get_setting("device_name", "LinkBridge-Windows"),
            platform=self.identity.platform,
        )
        return self.identity

    def revoke_peer(self, peer_device_id: str) -> None:
        """Revoke a paired device in SQLite and terminate its active sessions."""
        self.storage.revoke_paired_device(peer_device_id)
        self.session_manager.revoke_device_sessions(peer_device_id)
        if self.active_transport and self.active_transport.peer_device_id == peer_device_id:
            try:
                self.active_transport.send_control(
                    MessageType.REVOKE_PAIRING,
                    {"device_id": self.identity.device_id, "reason": "Pairing revoked by user"},
                )
            except Exception:
                pass
            self.active_transport.close()
            self.active_transport = None

    def authenticate_as_server(
        self,
        transport: TransportAdapter,
        use_secret_instead_of_pin: bool = False,
    ) -> SessionInfo:
        trusted = self.storage.get_trusted_peers_map()
        active_token = self.active_secret_hex if use_secret_instead_of_pin else self.active_pin
        session_info = transport.server_handshake_and_pair_or_auth(
            pairing_manager=self.pairing_manager,
            session_manager=self.session_manager,
            trusted_peers=trusted,
            active_pin_or_secret=active_token,
            pairing_approval_callback=self.pairing_approval_callback,
        )
        # Persist newly paired or updated peer record in SQLite
        if transport.peer_device_id and transport.peer_device_id in trusted:
            self.storage.save_paired_device(trusted[transport.peer_device_id])
        self.active_transport = transport
        self._emit(
            "CONNECTED",
            {
                "peer_device_id": transport.peer_device_id,
                "peer_device_name": transport.peer_device_name,
                "transport": transport.transport_type.value,
            },
        )
        return session_info

    def authenticate_as_client(
        self,
        transport: TransportAdapter,
        pin_or_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        trusted = self.storage.get_trusted_peers_map()
        peer_record = transport.client_handshake_and_pair_or_auth(
            pairing_manager=self.pairing_manager,
            trusted_peers=trusted,
            pin_or_secret=pin_or_secret,
        )
        self.storage.save_paired_device(peer_record)
        self.active_transport = transport
        self._emit(
            "CONNECTED",
            {
                "peer_device_id": transport.peer_device_id,
                "peer_device_name": transport.peer_device_name,
                "transport": transport.transport_type.value,
            },
        )
        return peer_record

    def process_next_incoming_operation(self, transport: Optional[TransportAdapter] = None) -> Dict[str, Any]:
        """
        Read and dispatch the next control/transfer message on an authenticated transport.
        Strictly validates `session_token` on every incoming operation before executing clipboard or file actions.
        """
        t = transport or self.active_transport
        if t is None or not t.is_connected:
            raise TransportError("لا يوجد اتصال نشط (No active transport)")

        frame: ProtocolFrame = t.receive_frame()
        mtype = frame.header.msg_type

        if mtype == MessageType.DISCONNECT:
            t.close()
            return {"type": "DISCONNECT"}

        body = frame.json_body()
        token = str(body.get("session_token", ""))

        # Enforce session token validation when this node is the session issuer (server) or when session is active
        if self.session_manager._sessions:
            valid, _, reason = self.session_manager.validate_session(token, expected_device_id=t.peer_device_id)
            if not valid:
                t.send_control(MessageType.ERROR, {"reason": reason})
                raise AuthenticationError(reason)
        elif not t.session_token or token != t.session_token:
            t.send_control(MessageType.ERROR, {"reason": "Unauthorized or missing session token"})
            raise AuthenticationError("Unauthorized or missing session token")

        if mtype == MessageType.PING:
            t.send_control(MessageType.PONG, {"ts": body.get("ts", 0)})
            return {"type": "PING"}

        if mtype == MessageType.CLIPBOARD_PUSH:
            res = self.clipboard_manager.handle_incoming_clipboard_push(t, body)
            return {"type": "CLIPBOARD_PUSH", "result": res}

        if mtype == MessageType.FILE_OFFER:
            res = self.file_manager.receive_offered_file(t, body, transfer_id=frame.header.transfer_id)
            return {"type": "FILE_OFFER", "result": res}

        if mtype == MessageType.REVOKE_PAIRING:
            if t.peer_device_id:
                self.storage.revoke_paired_device(t.peer_device_id)
                self.session_manager.revoke_device_sessions(t.peer_device_id)
            t.close()
            return {"type": "REVOKE_PAIRING"}

        t.send_control(MessageType.ERROR, {"reason": f"Unhandled message type: {mtype}"})
        return {"type": "ERROR", "reason": f"Unhandled message type: {mtype}"}

    # ------------------------------------------------------------------
    # Local Wi-Fi / Hotspot TCP+TLS Listener (stops cleanly when disabled)
    # ------------------------------------------------------------------
    def enable_live_dispatcher(self, transport: Optional[TransportAdapter] = None) -> None:
        t = transport or self.active_transport
        if t is None:
            return

        def _on_incoming() -> None:
            with self._op_lock:
                try:
                    self.process_next_incoming_operation(t)
                except Exception as e:
                    self._emit("TRANSFER_ERROR", {"reason": str(e)})

        t.start_background_dispatcher(_on_incoming)

    def start_wifi_listener(
        self,
        bind_ip: str = "127.0.0.1",
        port: int = DEFAULT_WIFI_PORT,
        is_hotspot: bool = False,
    ) -> Tuple[str, int]:
        """
        Start listening for incoming TLS connections on the specified local IP and port.
        Stops listening immediately when `stop_wifi_listener()` is called.
        """
        self.stop_wifi_listener()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(0.2)
        srv.bind((bind_ip, port))
        srv.listen(5)
        actual_ip, actual_port = srv.getsockname()
        self._server_sock = srv
        self._listening = True

        def _accept_loop() -> None:
            while self._listening:
                try:
                    client_sock, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    tls_transport = WifiTlsTransport.wrap_accepted_socket(
                        self.identity,
                        client_sock,
                        is_hotspot=is_hotspot,
                    )
                    self.authenticate_as_server(tls_transport)
                    self.enable_live_dispatcher(tls_transport)
                except Exception as e:
                    if "DISCOVER_PING_HANDLED" not in str(e):
                        self._emit("AUTH_ERROR", {"reason": str(e)})
                    try:
                        client_sock.close()
                    except OSError:
                        pass

        self._server_thread = threading.Thread(target=_accept_loop, daemon=True)
        self._server_thread.start()
        return actual_ip, actual_port

    def stop_wifi_listener(self) -> None:
        """Stop the local Wi-Fi listener socket immediately."""
        self._listening = False
        self._op_lock = threading.Lock()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)
        self._server_thread = None

    def shutdown(self) -> None:
        self.stop_wifi_listener()
        if self.active_transport:
            self.active_transport.close()
            self.active_transport = None
        self.storage.close()
