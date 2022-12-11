import abc
import logging
from typing import Literal

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest


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


class Icmpv6QueryFactory(QueryFactory):
    def get_query(self):
        return ICMPv6EchoRequest()


class IpQueryFactory(abc.ABC):
    @abc.abstractmethod
    def get_query(self, ttl: int):
        pass


class Ipv4QueryFactory(IpQueryFactory):
    def __init__(self, ip, protocol: Literal['tcp', 'udp', 'icmp'], port: int = None):
        self.__ip = ip
        self.__factory = self.__get_query_factory(protocol, port)

    def get_query(self, ttl: int):
        return IP(dst=self.__ip, ttl=ttl) / self.__factory.get_query()

    @staticmethod
    def __get_query_factory(protocol: Literal['tcp', 'udp', 'icmp'], port: int):
        if protocol == 'tcp':
            return TcpQueryFactory(port)
        elif protocol == 'udp':
            return UdpQueryFactory(port)
        elif protocol == 'icmp':
            return IcmpQueryFactory()


class Ipv6QueryFactory(IpQueryFactory):
    def __init__(self, ip, protocol: Literal['tcp', 'udp', 'icmp'], port: int = None):
        self.__ip = ip
        self.__factory = self.__get_query_factory(protocol, port)

    def get_query(self, ttl: int):
        return IPv6(dst=self.__ip, hlim=ttl) / self.__factory.get_query()

    @staticmethod
    def __get_query_factory(protocol: Literal['tcp', 'udp', 'icmp'], port: int):
        if protocol == 'tcp':
            return TcpQueryFactory(port)
        elif protocol == 'udp':
            return UdpQueryFactory(port)
        elif protocol == 'icmp':
            return Icmpv6QueryFactory()
