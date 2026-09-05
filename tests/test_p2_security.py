import gzip
import json
import subprocess
import unittest
from pathlib import Path
from threading import BoundedSemaphore
from unittest.mock import Mock, patch

import requests
from bs4 import BeautifulSoup

from api.app import (
    ALLOWED_IMAGE_DOMAINS, BASE_DIR, app, all_request_times, request_times,
    parse_post_html, process_payload, read_limited_html, safe_image_url,
)


class ResourceTests(unittest.TestCase):
    def response(self, chunks, **headers):
        response = requests.Response()
        response.encoding = "utf-8"
        response.headers.update(headers)
        response.raw = Mock()
        response.raw.stream.return_value = iter(chunks)
        return response

    def test_plain_and_gzip_html_are_decoded(self):
        text = '<div class="write_div">본문</div>'
        for data, headers in ((text.encode(), {}), (gzip.compress(text.encode()), {"Content-Encoding": "gzip"})):
            with self.subTest(headers=headers):
                response = self.response([data[:10], data[10:]], **headers)
                self.assertEqual(read_limited_html(response), text)
                response.raw.stream.assert_called_once_with(16384, decode_content=False)

    def test_announced_oversize_is_rejected_without_reading(self):
        response = self.response([b"never read"], **{"Content-Length": "999999999"})
        with self.assertRaises(ValueError):
            read_limited_html(response)
        response.raw.stream.assert_not_called()

    def test_missing_or_false_content_length_does_not_bypass_limit(self):
        for headers in ({}, {"Content-Length": "1"}):
            response = self.response([b"a" * 100, b"b" * 100], **headers)
            with patch("api.app.MAX_HTML_BYTES", 128), self.assertRaises(ValueError):
                read_limited_html(response)

    def test_gzip_bomb_is_bounded_during_decompression(self):
        bomb = gzip.compress(b"x" * 100000)
        with patch("api.app.MAX_HTML_BYTES", 1024), self.assertRaises(ValueError):
            read_limited_html(self.response([bomb], **{"Content-Encoding": "gzip"}))

    def test_unexpected_types_encodings_and_broken_gzip_are_rejected(self):
        cases = [
            ([b"pdf"], {"Content-Type": "application/pdf"}),
            ([b"br"], {"Content-Encoding": "br"}),
            ([b"invalid"], {"Content-Encoding": "gzip"}),
            ([gzip.compress(b"text")[:-4]], {"Content-Encoding": "gzip"}),
            ([gzip.compress(b"a") + gzip.compress(b"b")], {"Content-Encoding": "gzip"}),
        ]
        for chunks, headers in cases:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                read_limited_html(self.response(chunks, **headers))

    def test_pasted_size_nodes_comments_and_depth_are_bounded(self):
        for html, constant, limit in (
            ('<div class="write_div">' + "가" * 100 + '</div>', "MAX_HTML_BYTES", 128),
            ('<div class="write_div">' + '<br>' * 30 + '</div>', "MAX_HTML_NODES", 20),
            ('<div class="write_div">' + '<!---->' * 30 + '</div>', "MAX_HTML_NODES", 20),
            ('<div>' * 30 + 'text' + '</div>' * 30, "MAX_HTML_DEPTH", 20),
        ):
            with self.subTest(constant=constant), patch("api.app." + constant, limit), self.assertRaises(ValueError):
                parse_post_html(html, "https://gall.dcinside.com/")


class PreviewTests(unittest.TestCase):
    def test_only_https_images_from_exact_approved_hosts_survive(self):
        allowed = "https://dcimg1.dcinside.com/viewimage.php?id=example"
        html = f'''<div class="write_div">Body
          <img src="{allowed}" onerror="alert(1)">
          <img src="https://tracker.invalid/pixel">
          <img src="http://127.0.0.1/private">
          <img src="https://dcimg1.dcinside.com.evil.invalid/pixel">
          <img src="https://dcimg1.dcinside.com:password@tracker.invalid/pixel">
          <img src="https://dcimg1.dcinside.com:8443/pixel">
          <img src="data:image/png;base64,AA==">
        </div>'''
        result = parse_post_html(html, "https://gall.dcinside.com/")
        self.assertEqual(result["image_count"], 1)
        image = BeautifulSoup(result["html"], "html.parser").img
        self.assertEqual(image["src"], allowed)
        self.assertEqual(image["referrerpolicy"], "no-referrer")
        self.assertNotIn("onerror", image.attrs)
        self.assertNotIn("<img", result["html_no_images"])

    def test_old_http_and_lazy_images_use_https(self):
        html = '<div class="write_div"><img data-src="//dcimg7.dcinside.co.kr/viewimage.php?id=x" src="placeholder"></div>'
        result = parse_post_html(html, "http://gall.dcinside.com/")
        self.assertIn('src="https://dcimg7.dcinside.co.kr/', result["html"])
        self.assertIsNone(safe_image_url("https://dcimg1.dcinside.com\\@evil.invalid/a"))

    def test_external_css_is_removed_in_both_image_modes(self):
        styles = [
            'background:url(https://tracker.invalid/pixel)',
            r'background:u\72l("https://tracker.invalid/pixel")',
            'background:image-set("https://tracker.invalid/pixel" 1x)',
            'background:-webkit-image-set("https://tracker.invalid/pixel" 1x)',
            'background:var(--image, url(https://tracker.invalid/pixel))',
            'background:cross-fade(url(https://tracker.invalid/a), red, 50%)',
            'background-image:url(https://tracker.invalid/pixel)',
        ]
        for style in styles:
            with self.subTest(style=style):
                html = f'<div class="write_div"><p style=\'{style}; color:red; font-size:16px\'>Body</p></div>'
                result = parse_post_html(html, "https://gall.dcinside.com/")
                for field in ("html", "html_no_images"):
                    self.assertNotIn("tracker.invalid", result[field])
                    self.assertIn("color:red", result[field])
                    self.assertIn("font-size:16px", result[field])

    def test_color_background_and_math_styles_are_preserved(self):
        html = '<div class="write_div"><p style="background:#eee;color:rgb(1,2,3);width:calc(100% - 2px)">Body</p></div>'
        output = parse_post_html(html, "https://gall.dcinside.com/")["html"]
        self.assertIn("background:#eee", output)
        self.assertIn("rgb(1,2,3)", output)
        self.assertIn("calc(100% - 2px)", output)

    def test_static_and_flask_csp_match_the_image_allowlist(self):
        soup = BeautifulSoup(Path(BASE_DIR, "index.html").read_text(encoding="utf-8"), "html.parser")
        policy = soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"})["content"]
        image_sources = policy.split(";", 1)[0].split()[1:]
        self.assertEqual(set(image_sources), {"https://" + host for host in ALLOWED_IMAGE_DOMAINS})
        with app.test_client().get("/") as response:
            self.assertEqual(response.headers["Content-Security-Policy"], policy)


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        request_times.clear()
        all_request_times.clear()
        self.slots = BoundedSemaphore(2)
        self.enterContext(patch("api.app.extraction_slots", self.slots))
        self.payload = {"html": '<div class="write_div">테스트 본문</div>'}

    def test_actual_worker_extracts_unicode_without_network(self):
        response = self.client.post("/api/extract", json=self.payload)
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["text"], "테스트 본문")

    def test_worker_timeout_kills_process_and_releases_slot(self):
        real_popen = subprocess.Popen
        processes = []

        def start(*args, **kwargs):
            # Actual extraction worker, not a sleeping thread or a mocked result.
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with patch("api.app.EXTRACTION_TIMEOUT", 0.001), patch("api.app.subprocess.Popen", side_effect=start):
            response = self.client.post("/api/extract", json=self.payload)
        self.assertEqual(response.status_code, 504)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(self.slots.acquire(blocking=False))
        self.assertTrue(self.slots.acquire(blocking=False))
        self.slots.release()
        self.slots.release()

    def test_oversized_requests_and_invalid_payloads_never_start_worker(self):
        with patch("api.app.run_bounded_extraction") as worker:
            with patch.dict(app.config, {"MAX_CONTENT_LENGTH": 128}):
                response = self.client.post("/api/extract", data=b"x" * 129, content_type="application/json")
                self.assertEqual(response.status_code, 413)
                self.assertFalse(response.json["ok"])
            with patch("api.app.MAX_HTML_BYTES", 32):
                self.assertEqual(self.client.post("/api/extract", json={"html": "가" * 20}).status_code, 413)
            for payload in ([], None, {"html": []}, {"url": 123}):
                self.assertEqual(self.client.post("/api/extract", data=json.dumps(payload), content_type="application/json").status_code, 400)
            self.assertEqual(self.client.post("/api/extract", data="{", content_type="application/json").status_code, 400)
            self.assertEqual(self.client.post("/api/extract", data=json.dumps(self.payload), content_type="text/plain").status_code, 415)
            worker.assert_not_called()

    def test_per_client_limit_cannot_be_bypassed_by_forwarded_header_and_expires(self):
        with patch("api.app.RATE_PER_CLIENT", 2), patch("api.app.time.monotonic", return_value=100) as clock, patch("api.app.run_bounded_extraction", side_effect=process_payload) as worker:
            for spoofed in ("1.1.1.1", "2.2.2.2"):
                self.assertEqual(self.client.post("/api/extract", json=self.payload, headers={"X-Forwarded-For": spoofed}).status_code, 200)
            response = self.client.post("/api/extract", json=self.payload, headers={"X-Forwarded-For": "3.3.3.3"})
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.headers["Retry-After"], "60")
            self.assertEqual(worker.call_count, 2)
            clock.return_value = 161
            self.assertEqual(self.client.post("/api/extract", json=self.payload).status_code, 200)

    def test_global_limit_bounds_rate_storage_for_many_clients(self):
        with patch("api.app.RATE_TOTAL", 2), patch("api.app.run_bounded_extraction", side_effect=process_payload):
            for number in range(10):
                response = self.client.post("/api/extract", json=self.payload, environ_overrides={"REMOTE_ADDR": f"192.0.2.{number}"})
                self.assertEqual(response.status_code, 200 if number < 2 else 429)
            self.assertEqual(len(request_times), 2)

    def test_concurrent_limit_refuses_work_instead_of_queueing(self):
        self.slots.acquire()
        self.slots.acquire()
        try:
            with patch("api.app.run_bounded_extraction") as worker:
                response = self.client.post("/api/extract", json=self.payload)
                self.assertEqual(response.status_code, 429)
                worker.assert_not_called()
        finally:
            self.slots.release()
            self.slots.release()


if __name__ == "__main__":
    unittest.main()
