import time
from socket import socket
from lib.help.settings import RATE

# reserve the original connect function
_connect = socket.connect


def hooked_connect(*args, **kwargs):
    # print('connection hooked')
    time.sleep(RATE)
    _connect(*args, **kwargs)
