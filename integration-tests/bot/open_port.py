
import socket
from contextlib import closing

def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

client_rpc=find_free_port()
chain_rpc=find_free_port()
print("JAIL_CLIENT_RPC={}".format(client_rpc))
print("JAIL_CHAIN_RPC={}".format(chain_rpc))
# write
f = open("run_open_port.sh", "w")
f.write("export JAIL_CLIENT_RPC={}\n".format(client_rpc))
f.write("export JAIL_CHAIN_RPC={}\n".format(chain_rpc))
f.write("export CLIENT_RPC_URL=http://localhost:{}\n".format(client_rpc))
f.write("export CHAIN_RPC_URL=http://localhost:{}\n".format(chain_rpc))
f.close()