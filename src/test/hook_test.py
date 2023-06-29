import socket
from lib.connection.HttpEntity import Request
from lib.connection.rate import hooked_connect

socket.socket.connect = hooked_connect

DUMMY_URL = 'https://jwc.scu.edu.cn/'
if __name__ == '__main__':
    res = Request("GET", DUMMY_URL).send()
    print(res.body)
