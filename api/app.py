from __future__ import annotations

import os
import re
from copy import copy
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup, NavigableString, Tag
from flask import Flask, jsonify, render_template, request, send_from_directory  # 👈 [send_from_directory 추가]
from bleach import clean
from bleach.css_sanitizer import CSSSanitizer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, template_folder=BASE_DIR, static_folder=BASE_DIR)

ALLOWED_DOMAINS = {
    "gall.dcinside.com",
    "m.dcinside.com",
    "www.dcinside.com",
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
    "img": ["src", "alt", "title", "width", "height", "style", "loading"],
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

css_sanitizer = CSSSanitizer(allowed_css_properties=ALLOWED_CSS_PROPERTIES)


def validate_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ValueError("링크를 입력하세요.")

    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("http 또는 https 링크만 사용할 수 있습니다.")

    host = parsed.netloc.lower().split(":", 1)[0]
    if host not in ALLOWED_DOMAINS:
        raise ValueError("현재는 dcinside.com 게시글 링크만 허용합니다.")

    return raw_url


def fetch_html(url: str) -> str:
    # 💡 디시인사이드 방화벽을 통과하기 위한 위장 신분증(Headers) 생성
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
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
    session = requests.Session()
    session.headers.update(headers)

    gallery_id = parse_qs(urlparse(url).query).get("id", [None])[0]
    if gallery_id:
        list_url = f"https://gall.dcinside.com/mgallery/board/lists/?id={gallery_id}"
        try:
            session.get(list_url, timeout=10)
        except requests.RequestException:
            pass  # 목록 방문이 실패해도 본문 요청은 계속 시도한다.

    response = session.get(url, timeout=10)
    response.raise_for_status()

    # requests가 인코딩을 못 잡으면 apparent_encoding을 사용한다.
    if not response.encoding or response.encoding.lower() == "iso-8859-1":
        response.encoding = response.apparent_encoding or "utf-8"
    return response.text


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

        absolute_src = urljoin(page_url, src)
        parsed = urlparse(absolute_src)
        if parsed.scheme not in {"http", "https"}:
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

        # 본문 폭을 넘지 않도록 기본 스타일을 추가한다.
        base_style = "max-width: 100%; height: auto; display: block; margin: 8px 0;"
        img["style"] = f"{old_style}; {base_style}" if old_style else base_style


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
        attributes=ALLOWED_ATTRIBUTES,
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


def parse_post_html(html: str, base_url: str) -> dict[str, str | int]:
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


@app.post("/api/extract")
def api_extract():
    try:
        payload = request.get_json(force=True) or {}
        pasted_html = (payload.get("html") or "").strip()

        if pasted_html:
            # 서버에서 직접 접속이 막힌 경우, 사용자가 브라우저에서 연 페이지의
            # 소스(Ctrl+U)를 붙여넣으면 같은 파싱 로직으로 추출한다.
            raw_url = (payload.get("url") or "").strip()
            base_url = raw_url if urlparse(raw_url).scheme in {"http", "https"} else DEFAULT_PASTE_BASE_URL
            try:
                data = parse_post_html(pasted_html, base_url)
            except ValueError:
                raise ValueError(
                    "붙여넣은 소스에서 본문 영역을 찾지 못했습니다. "
                    "게시글 페이지에서 마우스 우클릭 → 페이지 소스 보기(Ctrl+U)로 연 뒤, "
                    "전체 내용을 그대로 복사해 붙여넣었는지 확인해주세요."
                )
            return jsonify({"ok": True, **data})

        url = validate_url(payload.get("url", ""))
        data = extract_post_body(url)
        return jsonify({"ok": True, **data})
    except requests.HTTPError as exc:
        return jsonify({"ok": False, "error": f"페이지 요청 실패: HTTP {exc.response.status_code}"}), 400
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": f"페이지 요청 실패: {exc}"}), 400
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"처리 중 오류가 발생했습니다: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

import os

# api 폴더의 상위(루트) 폴더 경로를 정확히 구합니다.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))