from lib.connection.HttpEntity import Request
from lib.connection.dns import get_cached_addr
import socket

socket.getaddrinfo = get_cached_addr
DUMMY_URL = 'https://jwc.scu.edu.cn/'

if __name__ == '__main__':
    """
    DNS Cache lessens RTT
    Most cases t2 < t1
    Sometimes t2 >= t1 due to network fluctuation
    """
    req1 = Request("GET", DUMMY_URL)
    t1 = req1.send().res.elapsed.microseconds

    req2 = Request("GET", DUMMY_URL)
    t2 = req2.send().res.elapsed.microseconds

    print("Before Cache: " + str(t1))
    print("After Cache: " + str(t2))
