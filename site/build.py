#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Собирает одностраничный HTML из README.md и docs/server-check.md.

Только стандартная библиотека: конвертер рассчитан на те конструкции
Markdown, которые используются в документации проекта.

Запуск:  python3 site/build.py
Результат: site/public/index.html
"""

import datetime
import html
import pathlib
import re

SITE_DIR = pathlib.Path(__file__).resolve().parent
ROOT = SITE_DIR.parent
OUT = SITE_DIR / "public" / "index.html"

TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}

BLOCK_START = re.compile(r"^(#{1,6}\s|```|\||>\s?|-\s|\d+\.\s|---+\s*$)")
LIST_ITEM = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")


def slugify(text: str, used: dict) -> str:
    plain = re.sub(r"[`*\[\]]", "", text).lower()
    plain = "".join(TRANSLIT.get(ch, ch) for ch in plain)
    slug = re.sub(r"[^a-z0-9]+", "-", plain).strip("-")[:60] or "section"
    count = used.get(slug, 0) + 1
    used[slug] = count
    return slug if count == 1 else "%s-%d" % (slug, count)


def inline(text: str) -> str:
    """Inline-разметка: `код`, **жирный**, *курсив*, [ссылка](url)."""
    pieces = re.split(r"(`[^`]+`)", text)
    out = []
    for piece in pieces:
        if len(piece) > 2 and piece.startswith("`") and piece.endswith("`"):
            out.append("<code>%s</code>" % html.escape(piece[1:-1]))
            continue
        escaped = html.escape(piece, quote=False)
        escaped = re.sub(
            r"\[([^\]]+)\]\(([^)\s]+)\)",
            lambda m: '<a href="%s">%s</a>'
            % (html.escape(m.group(2), quote=True), m.group(1)),
            escaped,
        )
        escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
        escaped = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", escaped)
        out.append(escaped)
    return "".join(out)


def is_table_separator(line: str) -> bool:
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", c) for c in cells)


def split_row(line: str):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def convert(source: str, doc_id: str, level_offset: int = 1):
    lines = source.splitlines()
    used: dict = {}
    toc = []
    out = []
    index = 0

    def flush_paragraph(buffer):
        if buffer:
            out.append("<p>%s</p>" % inline(" ".join(buffer)))
            buffer.clear()

    paragraph = []

    while index < len(lines):
        line = lines[index]

        if not line.strip():
            flush_paragraph(paragraph)
            index += 1
            continue

        fence = re.match(r"^```(\S*)\s*$", line)
        if fence:
            flush_paragraph(paragraph)
            lang = fence.group(1)
            index += 1
            code = []
            while index < len(lines) and not lines[index].startswith("```"):
                code.append(lines[index])
                index += 1
            index += 1
            attr = ' data-lang="%s"' % html.escape(lang) if lang else ""
            out.append(
                "<pre%s><code>%s</code></pre>"
                % (attr, html.escape("\n".join(code)))
            )
            continue

        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            flush_paragraph(paragraph)
            raw = heading.group(2).strip()
            level = min(6, len(heading.group(1)) + level_offset)
            anchor = slugify(raw, used)
            toc.append((level, anchor, re.sub(r"[`*]", "", raw)))
            out.append(
                '<h%d id="%s">%s<a class="anchor" href="#%s">#</a></h%d>'
                % (level, anchor, inline(raw), anchor, level)
            )
            index += 1
            continue

        if line.strip().startswith("|") and index + 1 < len(lines) and is_table_separator(lines[index + 1]):
            flush_paragraph(paragraph)
            header = split_row(line)
            index += 2
            rows = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                rows.append(split_row(lines[index]))
                index += 1
            body = ["<table>", "<thead><tr>"]
            body.extend("<th>%s</th>" % inline(cell) for cell in header)
            body.append("</tr></thead><tbody>")
            for row in rows:
                body.append(
                    "<tr>%s</tr>" % "".join("<td>%s</td>" % inline(c) for c in row)
                )
            body.append("</tbody></table>")
            out.append("\n".join(body))
            continue

        if re.fullmatch(r"-{3,}\s*", line):
            flush_paragraph(paragraph)
            out.append("<hr>")
            index += 1
            continue

        if line.startswith(">"):
            flush_paragraph(paragraph)
            quoted = []
            while index < len(lines) and lines[index].startswith(">"):
                quoted.append(lines[index].lstrip(">").strip())
                index += 1
            out.append("<blockquote>%s</blockquote>" % inline(" ".join(quoted)))
            continue

        item = LIST_ITEM.match(line)
        if item:
            flush_paragraph(paragraph)
            ordered = re.match(r"\d+\.", item.group(2))
            start_number = int(item.group(2)[:-1]) if ordered else 1
            entries = []
            while index < len(lines):
                current = lines[index]
                match = LIST_ITEM.match(current)
                if match:
                    entries.append([match.group(3).strip()])
                    index += 1
                    continue
                if not current.strip():
                    lookahead = index + 1
                    while lookahead < len(lines) and not lines[lookahead].strip():
                        lookahead += 1
                    if lookahead < len(lines) and LIST_ITEM.match(lines[lookahead]):
                        index = lookahead
                        continue
                    break
                if current.startswith("  ") and entries:
                    entries[-1].append(current.strip())
                    index += 1
                    continue
                break
            tag = "ol" if ordered else "ul"
            attr = ' start="%d"' % start_number if ordered and start_number != 1 else ""
            out.append("<%s%s>" % (tag, attr))
            for entry in entries:
                text = " ".join(entry)
                task = re.match(r"\[([ xX])\]\s+(.*)$", text)
                if task:
                    css = "task done" if task.group(1).lower() == "x" else "task"
                    out.append(
                        '<li class="%s"><span class="box"></span>%s</li>'
                        % (css, inline(task.group(2)))
                    )
                else:
                    out.append("<li>%s</li>" % inline(text))
            out.append("</%s>" % tag)
            continue

        paragraph.append(line.strip())
        index += 1

    flush_paragraph(paragraph)
    return "\n".join(out), toc


def nav_html(toc):
    parts = ['<nav class="toc" aria-label="Содержание"><h2>Содержание</h2><ul>']
    for level, anchor, title in toc:
        if level > 4:
            continue
        css = "toc-h2" if level == 2 else ("toc-h3" if level == 3 else "toc-h4")
        parts.append(
            '<li class="%s"><a href="#%s">%s</a></li>'
            % (css, anchor, html.escape(title))
        )
    parts.append("</ul></nav>")
    return "\n".join(parts)


CSS = """
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --ink: #16181d;
  --muted: #5b6472;
  --line: #e2e6ee;
  --accent: #1f6feb;
  --accent-soft: #e8f0fe;
  --code-bg: #11151c;
  --code-ink: #e6edf3;
  --warn: #9a3412;
  --ok: #166534;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg: #0d1117;
    --panel: #151b23;
    --ink: #e6edf3;
    --muted: #9aa7b7;
    --line: #253040;
    --accent: #58a6ff;
    --accent-soft: #16243a;
    --code-bg: #0a0e14;
    --code-ink: #e6edf3;
  }
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 16px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        "Helvetica Neue", Arial, sans-serif;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1240px; margin: 0 auto; padding: 0 24px; }
header.hero {
  background: linear-gradient(135deg, #0b1f3a 0%, #123a63 55%, #1f6feb 100%);
  color: #fff;
  padding: 56px 0 46px;
}
header.hero .wrap { position: relative; }
header.hero h1 {
  margin: 0 0 12px;
  font-size: clamp(30px, 4.2vw, 46px);
  letter-spacing: -0.02em;
}
header.hero p.lead {
  margin: 0 0 22px;
  max-width: 780px;
  font-size: 18px;
  color: #d5e3f7;
}
.badges { display: flex; flex-wrap: wrap; gap: 8px; }
.badge {
  border: 1px solid rgba(255,255,255,.35);
  border-radius: 999px;
  padding: 4px 12px;
  font-size: 13px;
  color: #eaf2ff;
  background: rgba(255,255,255,.08);
}
.layout {
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  gap: 36px;
  padding: 36px 0 72px;
  align-items: start;
}
nav.toc {
  position: sticky;
  top: 24px;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 18px 20px;
  max-height: calc(100vh - 48px);
  overflow: auto;
}
nav.toc h2 {
  margin: 0 0 10px;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--muted);
}
nav.toc ul { list-style: none; margin: 0; padding: 0; }
nav.toc li { margin: 2px 0; font-size: 14px; }
nav.toc li.toc-h3 { padding-left: 14px; font-size: 13px; }
nav.toc li.toc-h4 { padding-left: 28px; font-size: 12.5px; }
nav.toc a { color: var(--ink); }
nav.toc a:hover { color: var(--accent); }
main { min-width: 0; }
section.doc {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 34px 40px 40px;
  margin-bottom: 28px;
  overflow-wrap: break-word;
}
section.doc > h2:first-child { margin-top: 0; }
h2, h3, h4 { line-height: 1.25; letter-spacing: -0.01em; }
h2 { font-size: 28px; margin: 40px 0 14px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
h3 { font-size: 21px; margin: 30px 0 10px; }
h4 { font-size: 17px; margin: 24px 0 8px; }
a.anchor { margin-left: 8px; opacity: 0; font-weight: 400; font-size: .8em; }
h2:hover a.anchor, h3:hover a.anchor, h4:hover a.anchor { opacity: .5; }
p { margin: 0 0 14px; }
ul, ol { margin: 0 0 16px; padding-left: 24px; }
li { margin: 5px 0; }
li.task { list-style: none; margin-left: -22px; }
li.task .box {
  display: inline-block;
  width: 15px; height: 15px;
  margin-right: 9px;
  border: 2px solid var(--muted);
  border-radius: 4px;
  vertical-align: -2px;
}
li.task.done .box { background: var(--ok); border-color: var(--ok); }
code {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .9em;
  background: var(--accent-soft);
  border-radius: 5px;
  padding: 1px 5px;
}
pre {
  position: relative;
  background: var(--code-bg);
  color: var(--code-ink);
  border-radius: 12px;
  padding: 18px 20px;
  overflow: auto;
  margin: 0 0 18px;
  font-size: 13.5px;
  line-height: 1.55;
}
pre code { background: none; padding: 0; color: inherit; font-size: inherit; }
pre[data-lang]::before {
  content: attr(data-lang);
  position: absolute;
  top: 0; right: 0;
  padding: 3px 10px;
  font: 11px/1.6 ui-monospace, monospace;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: #8b98a9;
  background: rgba(255,255,255,.06);
  border-radius: 0 12px 0 8px;
}
blockquote {
  margin: 0 0 18px;
  padding: 12px 18px;
  border-left: 3px solid var(--accent);
  background: var(--accent-soft);
  border-radius: 0 10px 10px 0;
  color: var(--ink);
}
table {
  width: 100%;
  border-collapse: collapse;
  margin: 0 0 20px;
  font-size: 14.5px;
}
th, td {
  text-align: left;
  padding: 9px 12px;
  border: 1px solid var(--line);
  vertical-align: top;
}
th { background: var(--accent-soft); font-weight: 600; }
tbody tr:nth-child(even) { background: rgba(127,127,127,.05); }
hr { border: 0; border-top: 1px solid var(--line); margin: 30px 0; }
footer {
  border-top: 1px solid var(--line);
  padding: 26px 0 40px;
  color: var(--muted);
  font-size: 14px;
}
footer .wrap { display: flex; gap: 18px; flex-wrap: wrap; justify-content: space-between; }
@media (max-width: 980px) {
  .layout { grid-template-columns: 1fr; }
  nav.toc { position: static; max-height: none; }
  section.doc { padding: 24px 20px 28px; }
}
@media print {
  header.hero { background: none; color: #000; padding: 0 0 16px; }
  nav.toc, a.anchor { display: none; }
  section.doc { border: 0; padding: 0; }
  pre { white-space: pre-wrap; }
}
"""


def build():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    server = (ROOT / "docs" / "server-check.md").read_text(encoding="utf-8")

    # Первый заголовок README становится заголовком секции.
    readme_body, readme_toc = convert(readme, "readme")
    server_body, server_toc = convert(server, "server")

    toc = nav_html(readme_toc + server_toc)
    stamp = datetime.date.today().isoformat()

    page = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nginx2root: проверка nginx — документация</title>
<meta name="description" content="Внешняя проверка подверженности nginx уязвимостям nginx2root (CVE-2026-123007, -123634, -123633, -121810, -113425) и пошаговая инструкция для сервера.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%231f6feb'/%3E%3Ctext x='32' y='44' font-size='34' font-family='monospace' text-anchor='middle' fill='white'%3En%3C/text%3E%3C/svg%3E">
<style>@@CSS@@</style>
</head>
<body>
<header class="hero">
  <div class="wrap">
    <h1>nginx2root: проверка nginx</h1>
    <p class="lead">Безопасная внешняя проверка подверженности nginx уязвимостям
      CVE-2026-123007, -123634, -123633, -121810 и -113425. Без эксплуатации:
      только рукопожатие, fingerprint и разбор конфигурации.</p>
    <div class="badges">
      <span class="badge">Python 3.8+</span>
      <span class="badge">только stdlib</span>
      <span class="badge">CLI + JSON</span>
      <span class="badge">версия 0.1.0</span>
    </div>
  </div>
</header>
<div class="wrap layout">
  <aside>@@TOC@@</aside>
  <main>
    <section class="doc">
@@README@@
    </section>
    <section class="doc">
@@SERVER@@
    </section>
  </main>
</div>
<footer>
  <div class="wrap">
    <span>Источник: README.md и docs/server-check.md репозитория nginx2root.</span>
    <span>Сборка: @@DATE@@</span>
  </div>
</footer>
</body>
</html>
"""
    page = (
        page.replace("@@CSS@@", CSS)
        .replace("@@TOC@@", toc)
        .replace("@@README@@", readme_body)
        .replace("@@SERVER@@", server_body)
        .replace("@@DATE@@", stamp)
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page, encoding="utf-8")
    print("written %s (%d bytes)" % (OUT, len(page.encode("utf-8"))))


if __name__ == "__main__":
    build()
