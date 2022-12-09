import abc
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.inet6 import IPv6


class QueryFactory(abc.ABC):
    @abc.abstractmethod
    def get_query(self):
        pass


class TcpQueryFactory(QueryFactory):
    def __init__(self, port):
        self.__port = port

    def get_query(self):
        return TCP(dport=self.__port, flags='S')


class UdpQueryFactory(QueryFactory):
    def __init__(self, port):
        self.__port = port

    def get_query(self):
        return UDP(dport=self.__port)


class IcmpQueryFactory(QueryFactory):

    def get_query(self):
        return ICMP()


class IpQueryFactory(abc.ABC):
    @abc.abstractmethod
    def get_query(self, ttl: int):
        pass


class Ipv4QueryFactory(IpQueryFactory):
    def __init__(self, ip, factory: QueryFactory):
        self.__ip = ip
        self.__factory = factory

    def get_query(self, ttl: int):
        return IP(dst=self.__ip, ttl=ttl) / self.__factory.get_query()


class Ipv6QueryFactory(IpQueryFactory):
    def __init__(self, ip, factory: QueryFactory):
        self.__ip = ip
        self.__factory = factory

    def get_query(self, ttl: int):
        return IPv6(dst=self.__ip, hlim=ttl) / self.__factory.get_query()
