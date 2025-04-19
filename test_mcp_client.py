# test_client.py
import socket
import json

msg = {
    "type": "call_tool",
    "tool": "append_nota",
    "arguments": {"nota": "nota desde cliente 1"}
}

with socket.create_connection(("127.0.0.1", 5050)) as s:
    s.sendall(json.dumps(msg).encode("utf-8"))
    response = s.recv(4096)
    print(json.loads(response.decode("utf-8")))
