from typing import Literal
from ipaddress import ip_address, IPv4Address, IPv6Address

import scapy.sendrecv
import contextlib
import ipwhois
from scapy.packet import Packet

import parser
import queryfactory

class Traceroute:
    def __init__(self, ip, query_factory: queryfactory.IpQueryFactory, max_queries_count, timeout, is_verbose):
        self.__ip = ip
        self.__query_factory = query_factory
        self.__max_queries_count = max_queries_count
        self.__timeout = timeout
        self.__is_verbose = is_verbose

    def traceroute(self):
        for i, (response, time) in enumerate(self.get_responses()):
            ip = response.src if response else None
            result = [i + 1, ip, time]
            if self.__is_verbose:
                result.append(_whois(ip))
            yield _convert_none_to_star(result)

    def get_responses(self):
        time_to_live = 0
        while self.__have_to_send_queries(time_to_live):
            time_to_live += 1
            response, time = self.__send_query(time_to_live)
            yield response, time
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
        response = scapy.sendrecv.sr1(query, timeout=self.__timeout, verbose=0)
        time = self.__get_time(query, response)
        return response, time

    def __get_time(self, sent_packet: Packet, received_packet: Packet):
        if received_packet:
            return _seconds_to_milliseconds(received_packet.time - sent_packet.sent_time)
        return _seconds_to_milliseconds(self.__timeout)

def _convert_none_to_star(elements: list):
    for element in elements:
        yield element if element else '*'

def _seconds_to_milliseconds(time_in_seconds):
    return round(time_in_seconds * 1000)

def _whois(ip: str):
    with contextlib.suppress(ipwhois.BaseIpwhoisException, ValueError):
        return _get_autonomous_system_number(ipwhois.IPWhois(ip))

def _get_autonomous_system_number(ip_whois: ipwhois.IPWhois):
    return ip_whois.lookup_whois()['asn']

def __get_ip_query_factory(ip: str, protocol: Literal['tcp', 'udp', 'icmp'], port: int = None):
    if __is_ipv4(ip):
        return queryfactory.Ipv4QueryFactory(ip, protocol, port)
    elif __is_ipv6(ip):
        return queryfactory.Ipv6QueryFactory(ip, protocol, port)


def __is_ipv4(ip: str):
    with contextlib.suppress(ValueError):
        return type(ip_address(ip)) is IPv4Address


def __is_ipv6(ip: str):
    with contextlib.suppress(ValueError):
        return type(ip_address(ip)) is IPv6Address


if __name__ == '__main__':
    arguments = parser.parse()
    ip_factory = __get_ip_query_factory(arguments.ip, arguments.protocol, arguments.p)
    traceroute = Traceroute(arguments.ip, ip_factory, arguments.n, arguments.t, arguments.v)
    for answer in traceroute.traceroute():
        print(*answer)
