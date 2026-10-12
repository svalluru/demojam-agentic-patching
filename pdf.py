"""A very small PDF writer — enough for a one-page status report.

Why not reportlab: the rest of this project is Python standard library only,
and QUICKSTART.md promises a new joiner there is nothing to pip install. A
dependency for one report would be the first thing to break that.

Scope is deliberately narrow — left-aligned text, rules, filled rectangles and
simple tables in the base-14 fonts, which need no embedding. No images, no
unicode beyond Latin-1, no flowing layout. If this ever needs more than that,
take the dependency rather than growing this file.

    doc = Doc()
    doc.text('Title', size=18, bold=True)
    doc.gap(6)
    doc.table(['Host', 'Outcome'], [['a.example', 'patched']], [320, 140])
    doc.save('out.pdf')
"""
from __future__ import annotations

import zlib
from pathlib import Path

# A4 at 72 dpi, which is what PDF measures in.
PAGE_W, PAGE_H = 595.28, 841.89
MARGIN = 48.0

# Base-14 fonts are guaranteed present in every reader, so nothing is embedded.
FONTS = {'regular': 'Helvetica', 'bold': 'Helvetica-Bold', 'mono': 'Courier'}

# Widths of Helvetica glyphs in 1/1000 em, indexed by codepoint 32..126. Only
# needed so that wrapping and right-alignment land in the right place; a
# monospace guess would misjudge a proportional font badly enough to overlap.
_HELV = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278,
    278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584,
    584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556,
    833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278,
    278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222,
    500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500,
    500, 334, 260, 334, 584,
)
_BOLD_EXTRA = 1.055      # Helvetica-Bold runs a little wider; close enough


def text_width(s: str, size: float, bold: bool = False, mono: bool = False) -> float:
    if mono:
        return len(s) * size * 0.6
    total = sum(_HELV[ord(c) - 32] if 32 <= ord(c) <= 126 else 556 for c in s)
    return total / 1000.0 * size * (_BOLD_EXTRA if bold else 1.0)


def wrap(s: str, width: float, size: float, bold: bool = False) -> list[str]:
    """Greedy word wrap to a pixel width. Breaks over-long words by character."""
    lines: list[str] = []
    for para in str(s).split('\n'):
        cur = ''
        for word in para.split(' '):
            trial = f'{cur} {word}'.strip()
            if cur and text_width(trial, size, bold) > width:
                lines.append(cur)
                cur = word
            else:
                cur = trial
            while text_width(cur, size, bold) > width:
                cut = len(cur)
                while cut > 1 and text_width(cur[:cut], size, bold) > width:
                    cut -= 1
                lines.append(cur[:cut])
                cur = cur[cut:]
        lines.append(cur)
    return lines or ['']


# The font dictionaries declare /WinAnsiEncoding, so cp1252 is the matching
# codec — and unlike latin-1 it actually contains the em dash, bullet and
# curly quotes this project's copy is full of. Encoding as latin-1 silently
# turned every one of them into '?'.
_FALLBACK = {0x2011: '-', 0x2012: '-', 0x2015: '-', 0x2212: '-',
             0x00a0: ' ', 0x2009: ' ', 0x202f: ' ', 0x2713: 'v', 0x2717: 'x'}


def esc(s: str) -> str:
    """Escape for a PDF literal string in WinAnsi (cp1252)."""
    out = str(s).translate(_FALLBACK)
    out = out.replace('\\', r'\\').replace('(', r'\(').replace(')', r'\)')
    return out.encode('cp1252', 'replace').decode('cp1252')


class Doc:
    """Builds a document top-down; `y` tracks the current baseline."""

    def __init__(self, page_w: float = PAGE_W, page_h: float = PAGE_H,
                 margin: float = MARGIN):
        self.w, self.h, self.margin = page_w, page_h, margin
        self.pages: list[list[str]] = []
        self._new_page()

    # -- page handling -----------------------------------------------------

    def _new_page(self) -> None:
        self.pages.append([])
        self.y = self.h - self.margin

    def _need(self, space: float) -> None:
        if self.y - space < self.margin:
            self._new_page()

    @property
    def _ops(self) -> list[str]:
        return self.pages[-1]

    @property
    def content_w(self) -> float:
        return self.w - 2 * self.margin

    # -- drawing -----------------------------------------------------------

    def text(self, s: str, size: float = 10, bold: bool = False,
             mono: bool = False, color: str = '#1a1a1a', x: float | None = None,
             leading: float | None = None) -> None:
        lead = leading if leading is not None else size * 1.35
        font = 'F3' if mono else ('F2' if bold else 'F1')
        for line in wrap(s, self.content_w if x is None else self.w - x - self.margin,
                         size, bold):
            self._need(lead)
            self.y -= lead
            self._ops.append(
                f'BT {self._rgb(color)} /{font} {size:.2f} Tf '
                f'1 0 0 1 {(x if x is not None else self.margin):.2f} {self.y:.2f} Tm '
                f'({esc(line)}) Tj ET')

    def gap(self, h: float = 8) -> None:
        self._need(h)
        self.y -= h

    def rule(self, color: str = '#d8d8d8', width: float = 0.6) -> None:
        self._need(6)
        self.y -= 4
        self._ops.append(
            f'{self._rgb(color, stroke=True)} {width} w '
            f'{self.margin:.2f} {self.y:.2f} m {self.w - self.margin:.2f} {self.y:.2f} l S')
        self.y -= 2

    def rect(self, x: float, y: float, w: float, h: float, color: str) -> None:
        self._ops.append(f'{self._rgb(color)} {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f')

    def banner(self, title: str, body: str, bg: str, fg: str = '#1a1205') -> None:
        """A filled callout. Height is measured before the box is drawn."""
        pad, tsize, bsize = 8.0, 10.5, 8.8
        lines = wrap(body, self.content_w - 2 * pad, bsize)
        h = pad * 2 + tsize * 1.35 + len(lines) * bsize * 1.3
        self._need(h + 6)
        top = self.y
        self.rect(self.margin, top - h, self.content_w, h, bg)
        self.y = top - pad
        self.text(title, size=tsize, bold=True, color=fg, x=self.margin + pad)
        for ln in lines:
            self.text(ln, size=bsize, color=fg, x=self.margin + pad, leading=bsize * 1.3)
        self.y = top - h - 6

    def table(self, headers: list[str], rows: list[list[str]], widths: list[float],
              size: float = 8.6, header_bg: str = '#eceff3',
              zebra: str = '#f7f8fa') -> None:
        """Rows wrap within their column and the row grows to fit."""
        pad, lead = 5.0, size * 1.3

        def row_h(cells: list[str]) -> tuple[float, list[list[str]]]:
            wrapped = [wrap(c, w - 2 * pad, size) for c, w in zip(cells, widths)]
            return max(len(c) for c in wrapped) * lead + 2 * pad, wrapped

        hh, hw = row_h(headers)
        self._need(hh + lead * 2)
        self._draw_row(hw, widths, hh, size, bold=True, bg=header_bg, pad=pad, lead=lead)
        for i, r in enumerate(rows):
            cells = [str(c) for c in r]
            rh, rw = row_h(cells)
            if self.y - rh < self.margin:
                self._new_page()
                self._draw_row(hw, widths, hh, size, bold=True, bg=header_bg,
                               pad=pad, lead=lead)
            self._draw_row(rw, widths, rh, size, bold=False,
                           bg=(zebra if i % 2 else None), pad=pad, lead=lead)

    def _draw_row(self, wrapped: list[list[str]], widths: list[float], h: float,
                  size: float, bold: bool, bg: str | None, pad: float,
                  lead: float) -> None:
        top = self.y
        if bg:
            self.rect(self.margin, top - h, sum(widths), h, bg)
        x = self.margin
        for cell, w in zip(wrapped, widths):
            yy = top - pad
            for line in cell:
                yy -= lead
                self._ops.append(
                    f'BT {self._rgb("#1a1a1a")} /{"F2" if bold else "F1"} {size:.2f} Tf '
                    f'1 0 0 1 {x + pad:.2f} {yy:.2f} Tm ({esc(line)}) Tj ET')
            x += w
        self.y = top - h

    @staticmethod
    def _rgb(hexcolor: str, stroke: bool = False) -> str:
        h = hexcolor.lstrip('#')
        r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
        return f'{r:.3f} {g:.3f} {b:.3f} {"RG" if stroke else "rg"}'

    # -- output ------------------------------------------------------------

    def save(self, path: str | Path) -> Path:
        n_pages = len(self.pages)
        # 1 catalog, 2 page tree, 3 fonts..., then one page + one stream each.
        font_ids = {'F1': 4, 'F2': 5, 'F3': 6}
        first = 7
        page_ids = [first + 2 * i for i in range(n_pages)]
        objs: dict[int, bytes] = {}

        objs[1] = b'<< /Type /Catalog /Pages 2 0 R >>'
        kids = ' '.join(f'{i} 0 R' for i in page_ids)
        objs[2] = (f'<< /Type /Pages /Count {n_pages} /Kids [{kids}] >>').encode()
        objs[3] = b'<< >>'
        for name, oid in font_ids.items():
            objs[oid] = (f'<< /Type /Font /Subtype /Type1 /BaseFont '
                         f'/{FONTS[{"F1": "regular", "F2": "bold", "F3": "mono"}[name]]} '
                         f'/Encoding /WinAnsiEncoding >>').encode()

        for i, ops in enumerate(self.pages):
            pid, sid = page_ids[i], page_ids[i] + 1
            fonts = ' '.join(f'/{n} {o} 0 R' for n, o in font_ids.items())
            objs[pid] = (
                f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.w:.2f} {self.h:.2f}] '
                f'/Resources << /Font << {fonts} >> >> /Contents {sid} 0 R >>').encode()
            raw = '\n'.join(ops).encode('cp1252', 'replace')
            comp = zlib.compress(raw)
            objs[sid] = (f'<< /Length {len(comp)} /Filter /FlateDecode >>\n'
                         f'stream\n').encode() + comp + b'\nendstream'

        out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        offsets: dict[int, int] = {}
        for oid in sorted(objs):
            offsets[oid] = len(out)
            out += f'{oid} 0 obj\n'.encode() + objs[oid] + b'\nendobj\n'

        xref_at = len(out)
        top = max(objs) + 1
        out += f'xref\n0 {top}\n'.encode()
        out += b'0000000000 65535 f \n'
        for oid in range(1, top):
            out += (f'{offsets[oid]:010d} 00000 n \n'.encode() if oid in offsets
                    else b'0000000000 65535 f \n')
        out += (f'trailer\n<< /Size {top} /Root 1 0 R >>\n'
                f'startxref\n{xref_at}\n%%EOF\n').encode()

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(bytes(out))
        return p
