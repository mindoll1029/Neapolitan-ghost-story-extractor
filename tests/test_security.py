"""Offline regression tests: DNS, TCP sockets and TLS handshakes are mocked."""

import io
import socket
import ssl
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from urllib3.util.ssl_ import resolve_cert_reqs

from api.app import BASE_DIR, MAX_REDIRECTS, app, validate_url, process_payload, request_times, all_request_times


class FakeSocket:
    def __init__(self, body=b"", status="200 OK", headers=()):
        lines = [f"HTTP/1.1 {status}", "Connection: close", f"Content-Length: {len(body)}"]
        lines.extend(headers)
        self.response = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
        self.sent = b""
        self.closed = False

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self.response)

    def sendall(self, data):
        self.sent += data

    def settimeout(self, timeout):
        pass

    def close(self):
        self.closed = True


def dns_record(value):
    family = socket.AF_INET6 if ":" in value else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (value, 443))


class SecurityTests(unittest.TestCase):
    def setUp(self):
        request_times.clear()
        all_request_times.clear()
        self.enterContext(patch("api.app.RATE_PER_CLIENT", 1000))
        self.enterContext(patch("api.app.RATE_TOTAL", 1000))
        # Socket-level tests run the worker function in-process; worker isolation
        # and timeout are exercised separately in test_p2_security.py.
        self.enterContext(patch("api.app.run_bounded_extraction", side_effect=process_payload))
        self.client = app.test_client()
        self.dns = self.enterContext(patch("api.app.socket.getaddrinfo", return_value=[dns_record("93.184.216.34")]))
        # Never use a real socket, including if a security check regresses.
        self.connect = self.enterContext(patch("api.app.create_connection"))
        self.tls = self.enterContext(patch(
            "urllib3.connection._ssl_wrap_socket_and_match_hostname",
            side_effect=lambda **kwargs: SimpleNamespace(socket=kwargs["sock"], is_verified=True),
        ))
        self.post = b'<span class="title_subject">Title</span><div class="write_div">Body<img src="/image.png"></div>'

    def extract(self, url):
        return self.client.post("/api/extract", json={"url": url})

    def test_userinfo_and_other_invalid_targets_never_connect(self):
        for url in (
            "http://gall.dcinside.com:dummy@127.0.0.1:7777/internal",
            "http://gall.dcinside.com:dummy@169.254.169.254/",
            "https://gall.dcinside.com@evil.invalid/",
            "https://user:password@gall.dcinside.com/",
            "https://gall.dcinside.com.evil.invalid/",
            "https://gall.dcinside.com:8443/",
            "https://gall.dcinside.com:80/",
            "http://gall.dcinside.com:443/",
            "https://gall.dcinside.com:invalid/",
            "https://gall.dcinside.com:99999/",
            "https://gall.dcinside.com\\@127.0.0.1/",
            "https://gall.dcinside.com\n/",
            "file:///etc/passwd", "http://[::1]/", 123,
        ):
            with self.subTest(url=url):
                self.assertEqual(self.extract(url).status_code, 400)
        self.dns.assert_not_called()
        self.connect.assert_not_called()

    def test_normal_urls_and_default_ports_are_accepted(self):
        for host in ("gall.dcinside.com", "m.dcinside.com", "www.dcinside.com"):
            self.assertEqual(validate_url(f"https://{host}:443/board/123#fragment"), f"https://{host}/board/123")
        self.assertEqual(validate_url(" HTTP://GALL.DCINSIDE.COM:80/ "), "http://gall.dcinside.com/")

    def test_private_special_and_mixed_dns_answers_never_connect(self):
        for ip in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
                   "0.0.0.0", "100.64.0.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1"):
            for answers in ([dns_record(ip)], [dns_record("93.184.216.34"), dns_record(ip)]):
                with self.subTest(ip=ip, mixed=len(answers) == 2):
                    self.dns.return_value = answers
                    self.assertEqual(self.extract("https://gall.dcinside.com/post").status_code, 400)
        self.connect.assert_not_called()

    def test_https_uses_verified_ip_but_keeps_domain_for_tls_and_host(self):
        sock = FakeSocket(self.post)
        self.connect.return_value = sock
        # Environment proxy settings must not replace the protected connection pool.
        with patch.dict("os.environ", {"HTTPS_PROXY": "http://127.0.0.1:8888"}):
            response = self.extract("https://gall.dcinside.com/post")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["title"], "Title")
        self.assertEqual(response.json["text"], "Body")
        self.assertEqual(response.json["image_count"], 1)
        self.assertEqual(self.connect.call_args.args[0], ("93.184.216.34", 443))
        self.assertEqual(self.dns.call_count, 1)
        self.assertEqual(self.tls.call_args.kwargs["server_hostname"], "gall.dcinside.com")
        self.assertEqual(resolve_cert_reqs(self.tls.call_args.kwargs["cert_reqs"]), ssl.CERT_REQUIRED)
        self.assertIn(b"Host: gall.dcinside.com\r\n", sock.sent)
        self.assertTrue(sock.closed)

    def test_http_and_public_ipv6_work(self):
        self.dns.return_value = [dns_record("2606:4700:4700::1111")]
        self.connect.return_value = FakeSocket(self.post)
        self.assertEqual(self.extract("http://m.dcinside.com/post").status_code, 200)
        self.assertEqual(self.connect.call_args.args[0], ("2606:4700:4700::1111", 80))
        self.tls.assert_not_called()

    def test_tls_certificate_failure_is_not_ignored(self):
        self.connect.return_value = FakeSocket(self.post)
        self.tls.side_effect = ssl.SSLError("certificate verify failed")
        self.assertEqual(self.extract("https://gall.dcinside.com/post").status_code, 400)

    def test_redirects_to_invalid_targets_are_blocked_before_second_connection(self):
        for target in ("http://127.0.0.1/", "https://evil.invalid/", "//169.254.169.254/",
                       "https://gall.dcinside.com:dummy@127.0.0.1/", "https://m.dcinside.com:8443/",
                       "http://m.dcinside.com/post", "file:///etc/passwd"):
            with self.subTest(target=target):
                self.connect.reset_mock()
                self.connect.return_value = FakeSocket(status="302 Found", headers=[f"Location: {target}"])
                self.assertEqual(self.extract("https://gall.dcinside.com/post").status_code, 400)
                self.assertEqual(self.connect.call_count, 1)

    def test_relative_and_allowed_domain_redirects_work(self):
        sockets = [
            FakeSocket(status="302 Found", headers=["Location: /next"]),
            FakeSocket(status="307 Temporary Redirect", headers=["Location: https://m.dcinside.com/post"]),
            FakeSocket(self.post),
        ]
        self.connect.side_effect = sockets
        self.assertEqual(self.extract("https://gall.dcinside.com/post").status_code, 200)
        self.assertIn(b"GET /next HTTP/1.1", sockets[1].sent)
        self.assertIn(b"Host: m.dcinside.com", sockets[2].sent)

    def test_dns_is_checked_again_on_redirect_connection(self):
        self.connect.return_value = FakeSocket(status="302 Found", headers=["Location: /next"])
        self.dns.side_effect = [[dns_record("93.184.216.34")], [dns_record("127.0.0.1")]]
        self.assertEqual(self.extract("https://gall.dcinside.com/post").status_code, 400)
        self.assertEqual(self.connect.call_count, 1)

    def test_redirect_loop_is_bounded(self):
        self.connect.side_effect = lambda *args, **kwargs: FakeSocket(status="302 Found", headers=["Location: /loop"])
        response = self.extract("https://gall.dcinside.com/loop")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.connect.call_count, MAX_REDIRECTS + 1)

    def test_gallery_warmup_also_blocks_unsafe_redirects(self):
        self.connect.return_value = FakeSocket(status="302 Found", headers=["Location: http://127.0.0.1/"])
        self.assertEqual(self.extract("https://gall.dcinside.com/post?id=napolitan").status_code, 400)
        self.assertEqual(self.connect.call_count, 1)

    def test_gallery_cookies_and_encoded_id_survive(self):
        listing = FakeSocket(headers=["Set-Cookie: gallery=ready; Path=/; Secure"])
        post = FakeSocket(self.post)
        self.connect.side_effect = [listing, post]
        self.assertEqual(self.extract("https://gall.dcinside.com/post?id=test%26next%3Dvalue").status_code, 200)
        self.assertIn(b"?id=test%26next%3Dvalue HTTP/1.1", listing.sent)
        self.assertIn(b"Cookie: gallery=ready", post.sent)

    def test_redirect_and_gallery_bodies_are_not_downloaded(self):
        class HeaderOnlyStream(io.BytesIO):
            def read(self, *args, **kwargs):
                raise AssertionError("Redirect/listing body must not be read")

        listing = FakeSocket(b"x" * 10000)
        redirect = FakeSocket(b"x" * 10000, status="302 Found", headers=["Location: /final"])
        for sock in (listing, redirect):
            sock.makefile = lambda *args, sock=sock, **kwargs: HeaderOnlyStream(sock.response)
        self.connect.side_effect = [listing, redirect, FakeSocket(self.post)]
        response = self.extract("https://gall.dcinside.com/post?id=napolitan")
        self.assertEqual(response.status_code, 200, response.json)
        self.assertTrue(listing.closed)
        self.assertTrue(redirect.closed)

    def test_socket_response_passes_through_decompressed_size_limit(self):
        import gzip
        self.connect.return_value = FakeSocket(
            gzip.compress(b"x" * 100000), headers=["Content-Encoding: gzip"],
        )
        with patch("api.app.MAX_HTML_BYTES", 1024):
            response = self.extract("https://gall.dcinside.com/post")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json["ok"])

    def test_network_errors_return_controlled_failure(self):
        self.dns.side_effect = socket.gaierror("offline")
        self.assertEqual(self.extract("https://gall.dcinside.com/post").status_code, 400)
        self.connect.assert_not_called()

    def test_static_source_paths_are_unreachable_and_home_still_works(self):
        old_prefix = "/" + Path(BASE_DIR).name
        for path in (old_prefix + "/api/app.py", old_prefix + "/requirements.txt",
                     "/static/api/app.py", "/api/app.py", "/requirements.txt", "/.env", "/.git/config"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)
        with self.client.get("/") as response:
            self.assertEqual(response.status_code, 200)
        self.assertNotIn("static", app.view_functions)

    def test_pasted_html_still_works_without_network(self):
        response = self.client.post("/api/extract", json={"html": self.post.decode()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["text"], "Body")
        self.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
