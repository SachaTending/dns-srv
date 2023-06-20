from loguru import logger
from dnslib import DNSRecord, RR, RCODE, DNSLabel
from socket import socket, AF_INET, SOCK_DGRAM
import json

__name__ = "TendingStream73's DNS Server"

logger.info("Starting...")

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('', 53))

def remove_suffix(text: str, t2: str) -> str: 
    if isinstance(text, DNSLabel): text = str(text)
    if text.endswith(t2): return text[:-len(t2)]
    else: return text

def handle(addr: tuple[str, int], data: bytes):
    logger.info(f"Received connection from {addr}")
    dnsrec = DNSRecord.parse(data)
    domain: str = dnsrec.q.qname
    logger.info(f"Request:\n{dnsrec}")
    logger.info(f"Looking for domain {domain} in domains.json")
    domains = json.load(open("domains.json"))
    for i in domains:
        if remove_suffix(domain, ".") == i:
            logger.info(f"{domain} = {domains[i]['A']}")
            out = dnsrec.reply()
            out.add_answer(*RR.fromZone(f"{remove_suffix(domain, '.')} A {domains[i]['A']}"))
            sock.sendto(out.pack(), addr)
            logger.success(f"{addr}({domain}) Done!")
            return
    logger.info("Domain not found in domains.json, trying to lookup in nodes")
    nodes = json.load(open("nodes.json"))
    for i in nodes:
        if isinstance(i, str):
            if not i.startswith("#"):
                a_pkt = dnsrec.send(i)
                ans = DNSRecord.parse(a_pkt)
                if ans.header.rcode == getattr(RCODE, "NXDOMAIN"):
                    continue
    logger.info("Domain not found.")
    resp = dnsrec.reply()
    resp.header.rcode = getattr(RCODE, "NXDOMAIN")
    sock.sendto(resp.pack(), addr)

logger.success("Ready!")

while True:
    logger.info("Waiting for data...")
    data, addr = sock.recvfrom(16384)
    logger.info(f"Got connection: {addr}")
    handle(addr, data)
    logger.success(f"Done processing {addr}")
