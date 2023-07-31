from loguru import logger
from dnslib import DNSRecord, RR, RCODE, DNSLabel, A, QTYPE
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
    try:
        dnsrec = DNSRecord.parse(data)
    except:
        logger.exception("Exception on decoding.")
        return
    domain: str = dnsrec.q.qname
    logger.info(f"Request:\n{dnsrec}")
    if dnsrec.q.qtype != getattr(QTYPE, "A"):
        rep = dnsrec.reply()
        rep.header.rcode = getattr(RCODE, "NXDOMAIN")
        logger.info("Requested invalid type, sending NXDOMAIN...")
        sock.sendto(rep.pack(), addr)
        return
    logger.info(f"Looking for domain {domain} in domains.json")
    domains = json.load(open("domains.json"))
    for i in domains:
        if remove_suffix(domain, ".") == i:
            logger.info(f"{domain} = {domains[i]['A']}")
            out = dnsrec.reply()
            out.add_answer(RR(remove_suffix(domain, "."), rdata=A(domains[i]['A'])))
            sock.sendto(out.pack(), addr)
            logger.success(f"{addr}({domain}) Done!")
            return
    logger.info("Domain not found in domains.json, trying to lookup in nodes")
    nodes = json.load(open("nodes.json"))
    for i in nodes:
        if isinstance(i, str):
            if not i.startswith("#"):
                try: a_pkt = dnsrec.send(i, timeout=10)
                except:
                    logger.info(f"Timeout on addr {addr}")
                    pass
                ans = DNSRecord.parse(a_pkt)
                if ans.header.rcode == getattr(RCODE, "NXDOMAIN"):
                    continue
                else:
                    logger.info("Domain found")
                    sock.sendto(a_pkt, addr)
                    return
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
