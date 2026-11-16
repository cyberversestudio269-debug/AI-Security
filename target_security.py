import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit

import dns.exception
import dns.resolver


MAX_RESPONSE_BYTES = 1024 * 1024


class UnsafeTargetError(ValueError):
    pass


def resolve_public_addresses(host, port):
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError("Target hostname could not be resolved.") from exc

    addresses = []
    for record in records:
        address = record[4][0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise UnsafeTargetError("Target hostname has no address records.")

    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise UnsafeTargetError("Target hostname must resolve only to public IP addresses.")
    return addresses


def parse_public_https_url(url):
    if not url or len(url) > 2048:
        raise UnsafeTargetError("Provide a valid HTTPS target URL.")
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise UnsafeTargetError("Targets must use HTTPS.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeTargetError("Target URLs must not contain credentials.")
    if parsed.fragment or parsed.query:
        raise UnsafeTargetError("Target URLs must not contain a fragment or query string.")

    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port or 443
    except (UnicodeError, ValueError) as exc:
        raise UnsafeTargetError("Target URL contains an invalid hostname or port.") from exc

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise UnsafeTargetError("Targets must use a DNS hostname, not an IP address.")

    addresses = resolve_public_addresses(host, port)
    return parsed, host, port, addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, port, timeout):
        context = ssl.create_default_context()
        super().__init__(host, port=port, timeout=timeout, context=context)
        self.address = address

    def connect(self):
        sock = socket.create_connection(
            (self.address, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def safe_https_request(method, url, body=None, headers=None, timeout=20):
    parsed, host, port, addresses = parse_public_https_url(url)
    connection = _PinnedHTTPSConnection(host, addresses[0], port, timeout)
    path = parsed.path or "/"
    host_header = host if port == 443 else "%s:%d" % (host, port)
    request_headers = {"Host": host_header}
    if headers:
        request_headers.update(headers)

    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise UnsafeTargetError("Target redirects are not followed.")
        if response.status < 200 or response.status >= 300:
            raise http.client.HTTPException(
                "Target returned HTTP status %d." % response.status
            )
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise UnsafeTargetError("Target response exceeded the size limit.")
        return payload
    finally:
        connection.close()


def safe_https_post_json(url, payload, headers=None, timeout=20):
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    body = json.dumps(payload).encode("utf-8")
    response = safe_https_request(
        "POST", url, body=body, headers=request_headers, timeout=timeout
    )
    return json.loads(response.decode("utf-8"))


def challenge_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_dns_challenge(host, expected_digest):
    name = "_ai-risk-scanner.%s" % host
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except dns.exception.DNSException:
        return False

    for answer in answers:
        value = b"".join(answer.strings).decode("utf-8", "replace").strip()
        if hashlib.sha256(value.encode("utf-8")).hexdigest() == expected_digest:
            return True
    return False


def verify_file_challenge(host, port, expected_digest):
    url = "https://%s/.well-known/ai-risk-scanner-verification.txt" % host
    if port != 443:
        url = "https://%s:%d/.well-known/ai-risk-scanner-verification.txt" % (host, port)
    value = safe_https_request("GET", url, timeout=10).decode("utf-8").strip()
    return hashlib.sha256(value.encode("utf-8")).hexdigest() == expected_digest
