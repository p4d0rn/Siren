from socket import getaddrinfo

dns_cache = {}


def get_cached_addr(*args, **kwargs):
    """
    override socket.getaddrinfo to get dns cached
    """
    host, port = args[:2]  # 前两个参数为host和port
    if host not in dns_cache:
        dns_cache[host] = getaddrinfo(*args, **kwargs)
    return dns_cache[host]
