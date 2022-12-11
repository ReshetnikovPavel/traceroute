import argparse


def parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    __add_args(parser)
    return parser.parse_args()


def __add_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('-t', help='таймаут ожидания ответа (по умолчанию 2с)', default=2, type=int)
    parser.add_argument('-p', help='порт (для tcp или udp)', type=int)
    parser.add_argument('-n', help='максимальное количество запросов', type=int)
    parser.add_argument('-v', help='вывод номера автономной системы для каждого ip-адреса',
                        action='store_true')
    parser.add_argument('ip', type=str)
    parser.add_argument('protocol', choices=['tcp', 'udp', 'icmp'], type=str)
