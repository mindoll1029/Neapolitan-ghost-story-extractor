from __future__ import annotations

import os
import re
import socket
import json
import subprocess
import sys
import time
import zlib
from collections import deque
from copy import copy
from ipaddress import ip_address
from html.parser import HTMLParser
from threading import BoundedSemaphore, Lock
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
import tinycss2
from bs4 import BeautifulSoup, NavigableString, Tag
from flask import Flask, jsonify, request, send_from_directory
from bleach import clean
from bleach.css_sanitizer import CSSSanitizer
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.util.connection import create_connection
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, static_folder=None)
MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_HTML_NODES = 20000
MAX_HTML_DEPTH = 100
EXTRACTION_TIMEOUT = 25
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024
app.json.ensure_ascii = False

# 인스턴스마다 적용한다. 여러 서버의 통합 제한은 배포 플랫폼/WAF에서 적용해야 한다.
RATE_WINDOW = 60
RATE_PER_CLIENT = 20
RATE_TOTAL = 60
request_times = {}
all_request_times = deque()
rate_lock = Lock()
extraction_slots = BoundedSemaphore(2)

ALLOWED_DOMAINS = {
    "gall.dcinside.com",
    "m.dcinside.com",
    "www.dcinside.com",
}
ALLOWED_IMAGE_DOMAINS = ALLOWED_DOMAINS | {"image.dcinside.com"} | {
    f"dcimg{number}.dcinside.{suffix}"
    for number in range(1, 10) for suffix in ("com", "co.kr")
}

BODY_SELECTORS = [
    "div.write_div",                 # PC 게시글 본문 기본값
    "div.writing_view_box",          # 모바일/일부 뷰어 대비
    "div.view_content_wrap div.write_div",
    "div.appending_file_box + div",  # 구조 변경 대비 보조값
]

ALLOWED_TAGS = [
    "p", "div", "span", "br",
    "b", "strong", "i", "em", "u", "s", "strike",
    "font", "blockquote", "center",
    "sub", "sup",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li",
    "table", "thead", "tbody", "tr", "td", "th",
    "img",
]

ALLOWED_ATTRIBUTES = {
    "*": ["style", "align"],
    "font": ["color", "size", "face", "style"],
    "td": ["colspan", "rowspan", "style", "align"],
    "th": ["colspan", "rowspan", "style", "align"],
    "img": ["src", "alt", "title", "width", "height", "style", "loading", "referrerpolicy"],
}

ALLOWED_CSS_PROPERTIES = [
    "color", "background", "background-color",
    "font", "font-family", "font-size", "font-weight", "font-style",
    "text-align", "text-decoration", "line-height", "letter-spacing",
    "margin", "margin-left", "margin-right", "margin-top", "margin-bottom",
    "padding", "padding-left", "padding-right", "padding-top", "padding-bottom",
    "border", "border-left", "border-right", "border-top", "border-bottom",
    "white-space",
    "width", "height", "max-width", "max-height", "min-width", "min-height",
    "display", "vertical-align",
]

ALLOWED_PROTOCOLS = ["http", "https"]

IMAGE_SOURCE_ATTRIBUTES = [
    "data-src", "data-original", "data-lazy", "data-url",
    "data-file", "file", "origin-src", "data-origin-src",
    "src",
]

class ResourceFreeCSSSanitizer(CSSSanitizer):
    def sanitize_css(self, style):
        def safe_tokens(tokens):
            for token in tokens:
                if token.type in {"url", "error"}:
                    return False
                if token.type == "function":
                    # URL을 문자열로 받는 image-set() 등도 거부한다.
                    if token.lower_name not in {"rgb", "rgba", "hsl", "hsla", "calc", "min", "max", "clamp"}:
                        return False
                    if not safe_tokens(token.arguments):
                        return False
                if hasattr(token, "content") and not safe_tokens(token.content):
                    return False
            return True

        declarations = tinycss2.parse_declaration_list(super().sanitize_css(style))
        return tinycss2.serialize([
            item for item in declarations
            if item.type == "declaration" and safe_tokens(item.value)
        ]).strip()


css_sanitizer = ResourceFreeCSSSanitizer(allowed_css_properties=ALLOWED_CSS_PROPERTIES)


def validate_url(raw_url: str) -> str:
    if not isinstance(raw_url, str):
        raise ValueError("링크는 문자열로 입력하세요.")
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ValueError("링크를 입력하세요.")

    if re.search(r"[\x00-\x20\x7f\\]", raw_url):
        raise ValueError("링크에 사용할 수 없는 문자가 포함되어 있습니다.")
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("http 또는 https 링크만 사용할 수 있습니다.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("사용자 인증 정보가 포함된 링크는 사용할 수 없습니다.")
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError("현재는 dcinside.com 게시글 링크만 허용합니다.")
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port not in {None, default_port}:
        raise ValueError("기본 HTTP/HTTPS 포트만 사용할 수 있습니다.")

    # 검증한 호스트로 주소를 다시 구성해 파서 간 해석 차이를 없앤다.
    return parsed._replace(netloc=parsed.hostname, fragment="").geturl()


class PublicConnectionMixin:
    def _new_conn(self):
        # 소켓 연결 시점에 모든 DNS 결과를 검사하고, 검사한 숫자 IP로만 접속한다.
        # 원래 host는 유지하므로 HTTPS 인증서 검증과 SNI는 도메인을 사용한다.
        if self.host not in ALLOWED_DOMAINS or self.port not in {80, 443}:
            raise ValueError("허용되지 않은 접속 대상입니다.")
        try:
            addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise NameResolutionError(self.host, self, exc) from exc
        if not addresses:
            raise NewConnectionError(self, "접속 주소를 찾을 수 없습니다.")
        ips = list(dict.fromkeys(address[4][0] for address in addresses))
        for value in ips:
            ip = ip_address(value)
            if not ip.is_global or ip.is_multicast or ip.is_reserved or "%" in value:
                raise ValueError("내부 또는 특수 IP 주소로는 접속할 수 없습니다.")
        for index, value in enumerate(ips):
            try:
                return create_connection(
                    (value, self.port), self.timeout,
                    source_address=self.source_address, socket_options=self.socket_options,
                )
            except OSError as exc:
                if index == len(ips) - 1:
                    if isinstance(exc, socket.timeout):
                        raise ConnectTimeoutError(self, "페이지 연결 시간이 초과되었습니다.") from exc
                    raise NewConnectionError(self, "페이지에 연결할 수 없습니다.") from exc


class PublicHTTPConnection(PublicConnectionMixin, HTTPConnection):
    pass


class PublicHTTPSConnection(PublicConnectionMixin, HTTPSConnection):
    pass


class PublicHTTPPool(HTTPConnectionPool):
    ConnectionCls = PublicHTTPConnection


class PublicHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = PublicHTTPSConnection


class PublicHTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": PublicHTTPPool, "https": PublicHTTPSPool,
        }

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        raise ValueError("페이지 요청에 프록시를 사용할 수 없습니다.")


MAX_REDIRECTS = 5


def discard_redirect_body(response, **kwargs):
    # Requests는 allow_redirects=False여도 다음 요청을 준비하며 리다이렉트 본문을
    # 읽는다. 응답 훅에서 먼저 닫아 크기 제한을 우회하는 다운로드를 막는다.
    if 300 <= response.status_code < 400:
        response.close()
        response._content = b""
        response._content_consumed = True
    return response


def safe_get(session: requests.Session, url: str) -> requests.Response:
    url = validate_url(url)
    for hop in range(MAX_REDIRECTS + 1):
        response = session.get(
            url, timeout=(5, 5), allow_redirects=False, stream=True,
            hooks={"response": discard_redirect_body},
        )
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        try:
            location = response.headers.get("Location")
            if not location:
                raise ValueError("이동할 주소가 없는 응답입니다.")
            if hop == MAX_REDIRECTS:
                raise ValueError("페이지 이동 횟수가 너무 많습니다.")
            next_url = validate_url(urljoin(url, location))
            if urlparse(url).scheme == "https" and urlparse(next_url).scheme != "https":
                raise ValueError("보안 연결에서 HTTP 주소로 이동할 수 없습니다.")
            url = next_url
        finally:
            response.close()


def read_limited_html(response: requests.Response) -> str:
    media_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if media_type and media_type not in {"text/html", "application/xhtml+xml"}:
        raise ValueError("HTML 페이지 응답만 가져올 수 있습니다.")
    length = response.headers.get("Content-Length")
    if length and (not length.isdecimal() or int(length) > MAX_HTML_BYTES):
        raise ValueError("가져올 페이지가 너무 큽니다. HTML은 2MiB까지 허용합니다.")
    encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
    if encoding not in {"identity", "gzip"}:
        raise ValueError("지원하지 않는 페이지 압축 형식입니다.")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
    result = bytearray()
    transferred = 0
    try:
        for chunk in response.raw.stream(16384, decode_content=False):
            transferred += len(chunk)
            if transferred > MAX_HTML_BYTES:
                raise ValueError("가져올 페이지가 너무 큽니다. HTML은 2MiB까지 허용합니다.")
            # 압축 폭탄이 거대한 중간 버퍼를 만들지 못하도록 해제 자체에 상한을 둔다.
            data = decoder.decompress(chunk, MAX_HTML_BYTES - len(result) + 1) if decoder else chunk
            result.extend(data)
            if len(result) > MAX_HTML_BYTES:
                raise ValueError("압축 해제된 HTML이 2MiB를 초과합니다.")
            if decoder and decoder.unused_data:
                raise ValueError("여러 압축 스트림이 포함된 응답은 허용하지 않습니다.")
        if decoder and not decoder.eof:
            raise ValueError("페이지의 압축 데이터가 완전하지 않습니다.")
    except zlib.error as exc:
        raise ValueError("페이지의 압축 데이터를 읽을 수 없습니다.") from exc
    # 이후 인코딩 추정도 이미 제한된 크기의 데이터만 사용한다.
    response._content = bytes(result)
    response._content_consumed = True
    if not response.encoding or response.encoding.lower() == "iso-8859-1":
        response.encoding = response.apparent_encoding or "utf-8"
    return response.text


def fetch_html(url: str) -> str:
    url = validate_url(url)
    # 💡 디시인사이드 방화벽을 통과하기 위한 위장 신분증(Headers) 생성
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, identity",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Referer": "https://gall.dcinside.com/",
    }

    # Vercel 같은 서버 환경(클라우드 IP)에서 접속하면 디시인사이드가 세션 쿠키 없는
    # 요청을 봇으로 의심해 차단하는 경우가 있어, 갤러리 목록을 먼저 방문해 정상 쿠키를
    # 받아온 뒤 같은 세션으로 게시글에 접근한다(실제 브라우저의 이동 경로를 모방).
    with requests.Session() as session:
        # 환경변수 프록시와 .netrc 인증 정보의 자동 사용을 막는다.
        session.trust_env = False
        session.mount("http://", PublicHTTPAdapter())
        session.mount("https://", PublicHTTPAdapter())
        session.headers.update(headers)

        gallery_id = parse_qs(urlparse(url).query).get("id", [None])[0]
        if gallery_id:
            list_url = "https://gall.dcinside.com/mgallery/board/lists/?" + urlencode({"id": gallery_id})
            try:
                with safe_get(session, list_url):
                    pass
            except requests.RequestException:
                pass  # 목록 방문의 통신 오류만 무시하고, 보안 검증 실패는 중단한다.

        with safe_get(session, url) as response:
            response.raise_for_status()
            return read_limited_html(response)


def find_body_node(soup: BeautifulSoup) -> Tag:
    for selector in BODY_SELECTORS:
        node = soup.select_one(selector)
        if node and (node.get_text(strip=True) or node.find("img")):
            return node

    # DCInside가 class명을 약간 바꾼 경우 대비: 본문성 텍스트가 가장 많은 후보 선택
    candidates = soup.find_all("div", class_=re.compile(r"write|content|view", re.I))
    candidates = [node for node in candidates if node.get_text(strip=True) or node.find("img")]
    if candidates:
        return max(candidates, key=lambda node: len(node.get_text(" ", strip=True)) + len(node.find_all("img")) * 80)

    raise ValueError("본문 영역을 찾지 못했습니다. 페이지 구조가 바뀌었거나 접근이 차단됐을 수 있습니다.")


def pick_image_src(img: Tag) -> str:
    for attr in IMAGE_SOURCE_ATTRIBUTES:
        value = (img.get(attr) or "").strip()
        if value and not value.lower().startswith("javascript:"):
            return value

    srcset = (img.get("srcset") or "").strip()
    if srcset:
        first = srcset.split(",", 1)[0].strip().split(" ", 1)[0].strip()
        if first and not first.lower().startswith("javascript:"):
            return first

    return ""


def normalize_images(node: Tag, page_url: str) -> None:
    for img in list(node.find_all("img")):
        src = pick_image_src(img)
        if not src:
            img.decompose()
            continue

        absolute_src = safe_image_url(src, page_url)
        if not absolute_src:
            img.decompose()
            continue

        alt = (img.get("alt") or "").strip()
        title = (img.get("title") or "").strip()
        width = (img.get("width") or "").strip()
        height = (img.get("height") or "").strip()
        old_style = (img.get("style") or "").strip()

        img.attrs.clear()
        img["src"] = absolute_src
        if alt:
            img["alt"] = alt
        if title:
            img["title"] = title
        if width and re.fullmatch(r"\d{1,5}", width):
            img["width"] = width
        if height and re.fullmatch(r"\d{1,5}", height):
            img["height"] = height
        img["loading"] = "lazy"
        img["referrerpolicy"] = "no-referrer"

        # 본문 폭을 넘지 않도록 기본 스타일을 추가한다.
        base_style = "max-width: 100%; height: auto; display: block; margin: 8px 0;"
        img["style"] = f"{old_style}; {base_style}" if old_style else base_style


def safe_image_url(src: str, page_url: str = "") -> str | None:
    try:
        if re.search(r"[\x00-\x20\x7f\\]", src):
            return None
        parsed = urlparse(urljoin(page_url, src))
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in ALLOWED_IMAGE_DOMAINS:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.port not in {None, 443 if parsed.scheme == "https" else 80}:
            return None
        return parsed._replace(scheme="https", netloc=parsed.hostname, fragment="").geturl()
    except ValueError:
        return None


def allowed_attribute(tag, name, value):
    if name not in ALLOWED_ATTRIBUTES.get(tag, []) + ALLOWED_ATTRIBUTES.get("*", []):
        return False
    return name != "src" or safe_image_url(value) == value


def remove_images(node: Tag) -> None:
    # 사진 OFF/텍스트 추출 상태에서는 이미지의 alt/title 값도 본문처럼 보이지 않게 완전히 제거한다.
    # DCInside 첨부 이미지의 alt 값이 긴 해시형 파일명으로 들어오는 경우가 있어, 텍스트로 대체하지 않는다.
    for img in list(node.find_all("img")):
        img.decompose()


def remove_brand_text_from_node(node: Tag) -> None:
    # 본문에 섞여 들어온 DCInside 표기만 제거한다.
    brand_pattern = re.compile(r"DC\s*Inside|DCInside", re.I)
    for string_node in list(node.find_all(string=True)):
        updated = brand_pattern.sub("", str(string_node))
        updated = re.sub(r"[ \t]{2,}", " ", updated)
        if updated != str(string_node):
            string_node.replace_with(NavigableString(updated))


def clean_body_node(node: Tag, page_url: str) -> None:
    # 본문 텍스트/이미지와 직접 관련 없는 요소 제거
    for bad in node.find_all([
        "script", "style", "iframe", "object", "embed", "noscript",
        "form", "button", "input", "select", "textarea", "video", "audio", "canvas",
    ]):
        bad.decompose()

    normalize_images(node, page_url)

    # 링크 자체는 제거하고 링크 안 텍스트/이미지는 남긴다.
    for a in node.find_all("a"):
        a.unwrap()

    # 디시 하단 앱 홍보 문구가 들어오는 경우 제거
    text_patterns = ["- dc official App"]
    for string_node in list(node.find_all(string=True)):
        if any(pattern in string_node for pattern in text_patterns):
            string_node.extract()

    remove_brand_text_from_node(node)


def sanitize_body_html(raw_html: str) -> str:
    return clean(
        raw_html,
        tags=ALLOWED_TAGS,
        attributes=allowed_attribute,
        protocols=ALLOWED_PROTOCOLS,
        css_sanitizer=css_sanitizer,
        strip=True,
    )


def normalize_empty_lines(html: str) -> str:
    html = re.sub(r"(?:\s*<br\s*/?>\s*){4,}", "<br><br><br>", html, flags=re.I)
    html = re.sub(r"\n{4,}", "\n\n\n", html)
    return html.strip()


def clean_title_text(title: str) -> str:
    title = title or ""

    # DCInside에서 작성자 옆 모바일 아이콘/보조 텍스트가 제목 문자열에 섞이는 경우 제거한다.
    title = re.sub(r"\s*앱에서\s*작성\s*", " ", title)

    # 혹시 DOM의 대체 텍스트가 다른 형태로 들어오는 경우까지 최소 보정한다.
    title = re.sub(r"\s*-\s*dc\s+official\s+App\s*", " ", title, flags=re.I)

    # 제목에 섞인 DCInside 표기는 제거한다.
    title = re.sub(r"DC\s*Inside|DCInside", "", title, flags=re.I)
    title = re.sub(r"\s{2,}", " ", title).strip()
    return title


class HTMLBudgetParser(HTMLParser):
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__()
        self.stack = []
        self.nodes = 0

    def count_node(self, *args):
        self.nodes += 1
        if self.nodes > MAX_HTML_NODES:
            raise ValueError("HTML 요소가 너무 많습니다.")

    handle_data = count_node
    handle_comment = count_node
    handle_decl = count_node
    handle_pi = count_node

    def handle_starttag(self, tag, attrs):
        self.count_node()
        if tag not in self.VOID_TAGS:
            self.stack.append(tag)
            if len(self.stack) > MAX_HTML_DEPTH:
                raise ValueError("HTML의 중첩 깊이가 너무 큽니다.")

    def handle_endtag(self, tag):
        if tag in self.stack:
            del self.stack[len(self.stack) - 1 - self.stack[::-1].index(tag):]


def parse_post_html(html: str, base_url: str) -> dict[str, str | int]:
    if len(html.encode("utf-8")) > MAX_HTML_BYTES:
        raise ValueError("HTML은 2MiB까지 허용합니다.")
    budget_parser = HTMLBudgetParser()
    budget_parser.feed(html)
    budget_parser.close()
    soup = BeautifulSoup(html, "html.parser")
    body_node = find_body_node(soup)
    clean_body_node(body_node, base_url)

    title_node = soup.select_one("span.title_subject, h3.title, .title_subject")
    if title_node:
        # 제목 안에 스크린리더/숨김용 보조 문구가 섞이는 경우 제외한다.
        # 예: <span class="blind">앱에서 작성</span>
        title_for_text = copy(title_node)
        for hidden_node in title_for_text.select(".blind"):
            hidden_node.decompose()
        title = clean_title_text(title_for_text.get_text(" ", strip=True))
    else:
        title = ""

    with_images_html = normalize_empty_lines(sanitize_body_html(body_node.decode_contents()))

    no_images_node = BeautifulSoup(str(body_node), "html.parser")
    remove_images(no_images_node)
    without_images_html = normalize_empty_lines(sanitize_body_html(no_images_node.decode_contents()))

    plain_text = BeautifulSoup(without_images_html, "html.parser").get_text("\n")
    plain_text = re.sub(r"\n{3,}", "\n\n", plain_text).strip()

    image_count = len(BeautifulSoup(with_images_html, "html.parser").find_all("img"))

    return {
        "title": title,
        "html": with_images_html,
        "html_no_images": without_images_html,
        "text": plain_text,
        "image_count": image_count,
    }


def extract_post_body(url: str) -> dict[str, str | int]:
    html = fetch_html(url)
    return parse_post_html(html, url)


DEFAULT_PASTE_BASE_URL = "https://gall.dcinside.com/"


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.after_request
def security_headers(response):
    # index.html의 meta 정책은 Vercel 정적 제공에도 적용된다.
    sources = " ".join("https://" + host for host in sorted(ALLOWED_IMAGE_DOMAINS))
    response.headers["Content-Security-Policy"] = f"img-src {sources}; object-src 'none'; base-uri 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def process_payload(payload):
    try:
        pasted_html = (payload.get("html") or "").strip()

        if pasted_html:
            # 서버에서 직접 접속이 막힌 경우, 사용자가 브라우저에서 연 페이지의
            # 소스(Ctrl+U)를 붙여넣으면 같은 파싱 로직으로 추출한다.
            raw_url = (payload.get("url") or "").strip()
            base_url = raw_url if urlparse(raw_url).scheme in {"http", "https"} else DEFAULT_PASTE_BASE_URL
            data = parse_post_html(pasted_html, base_url)
            return {"ok": True, **data}, 200

        url = validate_url(payload.get("url", ""))
        data = extract_post_body(url)
        return {"ok": True, **data}, 200
    except requests.HTTPError as exc:
        return {"ok": False, "error": f"페이지 요청 실패: HTTP {exc.response.status_code}"}, 400
    except requests.RequestException:
        return {"ok": False, "error": "페이지에 연결할 수 없습니다. 잠시 후 다시 시도하세요."}, 400
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}, 400
    except Exception:
        return {"ok": False, "error": "페이지를 처리할 수 없습니다."}, 500


def run_bounded_extraction(payload):
    # 스레드의 timeout은 작업을 중단하지 못한다. DNS/다운로드/파싱 전체를
    # 종료할 수 있도록 별도 프로세스에서 실행한다. 셸에는 사용자 입력을 넘기지 않는다.
    worker_env = os.environ.copy()
    # 서버리스 런타임이 추가한 의존성 경로도 자식 Python에서 사용할 수 있게 한다.
    worker_env["PYTHONPATH"] = os.pathsep.join(path for path in sys.path if path)
    try:
        result = subprocess.run(
            [sys.executable, "-B", os.path.abspath(__file__), "--extract-worker"],
            input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            capture_output=True, timeout=EXTRACTION_TIMEOUT,
            env=worker_env,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "추출 시간이 25초를 초과하여 중단했습니다."}, 504
    if result.returncode or len(result.stdout) > MAX_RESULT_BYTES:
        return {"ok": False, "error": "페이지를 처리할 수 없습니다."}, 500
    return json.loads(result.stdout)


@app.before_request
def limit_extract_requests():
    if request.path != "/api/extract" or request.method != "POST":
        return None
    now = time.monotonic()
    # 임의로 조작할 수 있는 X-Forwarded-For를 클라이언트 식별에 사용하지 않는다.
    client = request.remote_addr or "unknown"
    with rate_lock:
        for key in list(request_times):
            times = request_times[key]
            while times and times[0] <= now - RATE_WINDOW:
                times.popleft()
            if not times:
                del request_times[key]
        while all_request_times and all_request_times[0] <= now - RATE_WINDOW:
            all_request_times.popleft()
        times = request_times.get(client, deque())
        if len(times) >= RATE_PER_CLIENT or len(all_request_times) >= RATE_TOTAL:
            return jsonify(ok=False, error="요청이 너무 많습니다. 1분 후 다시 시도하세요."), 429, {"Retry-After": str(RATE_WINDOW)}
        times.append(now)
        request_times[client] = times
        all_request_times.append(now)


@app.errorhandler(RequestEntityTooLarge)
def too_large(exc):
    return jsonify(ok=False, error="입력 데이터가 너무 큽니다. 요청은 3MiB, HTML은 2MiB까지 허용합니다."), 413


@app.post("/api/extract")
def api_extract():
    try:
        payload = request.get_json()
        if not isinstance(payload, dict):
            raise ValueError("JSON 객체를 입력하세요.")
        for field in ("html", "url"):
            value = payload.get(field, "")
            if not isinstance(value, str):
                raise ValueError("HTML과 링크는 문자열로 입력하세요.")
            limit = MAX_HTML_BYTES if field == "html" else 8192
            if len(value.encode("utf-8")) > limit:
                raise RequestEntityTooLarge()
        if not extraction_slots.acquire(blocking=False):
            return jsonify(ok=False, error="다른 추출 작업을 처리 중입니다. 잠시 후 다시 시도하세요."), 429, {"Retry-After": "5"}
        try:
            data, status = run_bounded_extraction({key: payload.get(key, "") for key in ("url", "html")})
            return jsonify(data), status
        finally:
            extraction_slots.release()
    except RequestEntityTooLarge:
        raise
    except UnsupportedMediaType:
        return jsonify(ok=False, error="application/json 형식으로 요청하세요."), 415
    except (BadRequest, ValueError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else "JSON 형식이 올바르지 않습니다."
        return jsonify(ok=False, error=message), 400
    except Exception:
        return jsonify(ok=False, error="추출 작업을 시작할 수 없습니다."), 500


if __name__ == "__main__":
    if sys.argv[1:] == ["--extract-worker"]:
        raw = sys.stdin.buffer.read(app.config["MAX_CONTENT_LENGTH"] + 1)
        if len(raw) > app.config["MAX_CONTENT_LENGTH"]:
            result = ({"ok": False, "error": "입력 데이터가 너무 큽니다."}, 413)
        else:
            result = process_payload(json.loads(raw))
        output = json.dumps(result, ensure_ascii=False).encode("utf-8")
        if len(output) > MAX_RESULT_BYTES:
            output = json.dumps([{"ok": False, "error": "추출 결과가 너무 큽니다."}, 413], ensure_ascii=False).encode("utf-8")
        sys.stdout.buffer.write(output)
    else:
        app.run(host="127.0.0.1", port=5000, debug=True)
