import argparse
import dns.resolver
import dns
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from functools import partial
import sys
from ipaddress import ip_address
import logging
import json

logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "names",
        nargs="*",
        help="Specify several domain or files. If None then stdin is used"
    )

    parser.add_argument(
        "--workers",
        "-w",
        default=10,
        type=int,
        help="Number of concurrent workers"
    )

    parser.add_argument(
        "--tcp",
        action="store_true",
        default=False,
        help="Use TCP"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Timeout milliseconds, default 5000"
    )

    parser.add_argument(
        "--nameservers",
        nargs="+",
        help="Custom name servers"
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        help="Verbosity",
        default=0
    )

    parser.add_argument(
        "-I", "--no-inputs",
        help="Do not show dns query input in result",
        action="store_true"
    )

    parser.add_argument(
        "-O", "--no-outputs",
        help="Do not show dns query output in result",
        action="store_true"
    )

    parser.add_argument(
        "-j", "--json",
        help="Results in json",
        action="store_true"
    )

    parser.add_argument(
        "-r", "--record",
        metavar="Q_TYPE",
        help="Record type to return.",
        default="",
    )

    args = parser.parse_args()
    args.timeout = args.timeout / 1000

    return args

def main():
    args = parse_args()
    init_log(args.verbose)

    pool = ThreadPoolExecutor(args.workers)
    print_lock = Lock()

    resolver = dns.resolver.Resolver()
    resolver.timeout = args.timeout

    if args.nameservers:
        resolver.nameservers = args.nameservers

    logger.info("Nameservers: %s", ", ".join(resolver.nameservers))

    partial_resolve = partial(
        get_q_types_resolver(args.record),
        resolver=resolver,
        tcp=args.tcp
    )

    if args.json:
        print_lines = print_json_lines
    else:
        print_lines = print_grep_lines

    partial_print_names = partial(
        print_lines,
        show_inputs=not args.no_inputs,
        show_outputs=not args.no_outputs
    )

    try:
        for hostname in read_input(args.names):
            pool.submit(
                dns_resolution,
                partial_resolve,
                hostname,
                print_lock,
                partial_print_names,
            )
    except (KeyboardInterrupt, BrokenPipeError):
        pass

def get_q_types_resolver(q_type):
    q_type = {
        "IPV4": "A",
        "IPV6": "AAAA",
        "INVERSE": "PTR",
    }.get(q_type.upper(), q_type.upper())

    try:
        return partial(resolve_record, dns.rdatatype.RdataType[q_type].name)
    except KeyError:
        if q_type != "":
            raise ValueError("Unknown record type: {}".format(q_type))
        return partial(resolve_domain_or_ip)

def resolve_domain_or_ip(host, resolver, tcp):
    if is_ip(host):
        return resolve_record("PTR", host, resolver, tcp)
    else:
        return resolve_record("A", host, resolver, tcp)


def is_ip(host):
    try:
        ip_address(host)
        return True
    except ValueError:
        return False

def resolve_record(q_type, host, resolver, tcp):
    logger.info("Resolving '%s' records %s", q_type, host)
    results = resolver.resolve(host, q_type, tcp=tcp)
    return [str(d) for d in results]

def dns_resolution(
        resolve_host,
        host,
        print_lock,
        print_names,
):
    try:
        outputs = resolve_host(host)
    except Exception as ex:
        logger.warning("Error '%s': %s", host, ex)
        raise ex

    with print_lock:
        print_names([host], outputs)


def init_log(verbosity=0, log_file=None):

    if verbosity == 1:
        level = logging.WARN
    elif verbosity == 2:
        level = logging.INFO
    elif verbosity > 2:
        level = logging.DEBUG
    else:
        level = logging.CRITICAL

    logging.basicConfig(
        level=level,
        filename=log_file,
        format="%(levelname)s:%(name)s:%(message)s"
    )


def read_input(names):
    if not names:
        for name in read_text_lines(sys.stdin):
            yield name
        return

    for name in names:
        try:
            with open(name) as fi:
                for line in read_text_lines(fi):
                    yield line
        except FileNotFoundError:
            # name must be a domain name
            yield name


def read_text_lines(fd):
    for line in fd:
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue

        yield line


def print_grep_lines(inputs, outputs, show_inputs=True, show_outputs=True):
    groups = []

    if show_inputs:
        groups.append(",".join(inputs))

    if show_outputs:
        groups.append(",".join(outputs))

    print(" ".join(groups), flush=True)


def print_json_lines(inputs, outputs, show_inputs=True, show_outputs=True):
    result = {}

    if show_inputs:
        result["inputs"] = inputs;

    if show_outputs:
        result["outputs"] = outputs

    print(json.dumps(result), flush=True)
