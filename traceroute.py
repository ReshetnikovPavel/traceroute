from typing import Literal
from ipaddress import ip_address, IPv4Address, IPv6Address

import scapy.sendrecv
import contextlib

import parser
import queryfactory


class Traceroute:
    def __init__(self, ip, query_factory: queryfactory.IpQueryFactory, max_queries_count, timeout):
        self.__ip = ip
        self.__query_factory = query_factory
        self.__max_queries_count = max_queries_count
        self.__timeout = timeout

    def traceroute(self):
        for i, response in enumerate(self.get_responses()):
            ip = response.src if response else '*'
            yield i + 1, ip

    def get_responses(self):
        time_to_live = 0
        while self.__have_to_send_queries(time_to_live):
            time_to_live += 1
            response = self.__send_query(time_to_live)
            yield response
            if self.__is_destination_response(response):
                return

    def __have_to_send_queries(self, queries_sent_count):
        if self.__max_queries_count:
            return queries_sent_count < self.__max_queries_count
        return True

    def __is_destination_response(self, response):
        return response and response.src == self.__ip

    def __send_query(self, ttl):
        query = self.__query_factory.get_query(ttl)
        return scapy.sendrecv.sr1(query, timeout=self.__timeout, verbose=0)


def __get_query_factory(protocol: Literal['tcp', 'udp', 'icmp'], port: int):
    if protocol == 'tcp':
        return queryfactory.TcpQueryFactory(port)
    elif protocol == 'udp':
        return queryfactory.UdpQueryFactory(port)
    elif protocol == 'icmp':
        return queryfactory.IcmpQueryFactory()


def __get_ip_query_factory(ip: str, factory: queryfactory.QueryFactory):
    if __is_ipv4(ip):
        return queryfactory.Ipv4QueryFactory(ip, factory)
    elif __is_ipv6(ip):
        return queryfactory.Ipv6QueryFactory(ip, factory)


def __is_ipv4(ip: str):
    with contextlib.suppress(ValueError):
        return type(ip_address(ip)) is IPv4Address


def __is_ipv6(ip: str):
    with contextlib.suppress(ValueError):
        return type(ip_address(ip)) is IPv6Address


if __name__ == '__main__':
    arguments = parser.parse()
    factory = __get_query_factory(arguments.protocol, arguments.p)
    ip_factory = __get_ip_query_factory(arguments.ip, factory)
    traceroute = Traceroute(arguments.ip, ip_factory, arguments.n, arguments.t)
    for answer in traceroute.traceroute():
        print(*answer)
