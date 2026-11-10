"""Human-readable rendering of a validated report (HC-REPORT-01 §5).

The validated report JSON (HC-FIND-01 §7) is the source of truth; this renders it as a
self-contained HTML page for the operator to read, hand off, or print, and the same output
is what the dashboard serves for a run (HC-REPORT-01 §6). It is a pure function with no
store and no server, so it is unit-tested directly.

Two properties it must hold. Times render in am/pm, not a 24-hour clock, since the stored
form is ISO-8601 UTC and the am/pm form is a render-time concern (BR-08). Every dynamic
value is HTML-escaped, so target strings and any model-authored text render as inert text,
never active markup (HC-REPORT-01 §3, §7). The report only carries text that already passed
`validate_report`, so no raw internal error detail reaches the page (BR-05). Standard
library only.
"""
import html
from datetime import datetime

_BANDS = {"critical": "#b00020", "high": "#d4511e", "medium": "#b7791f",
          "low": "#2f6f4e", "none": "#5b6470"}


def am_pm(iso):
    """Render an ISO-8601 timestamp in am/pm human form, e.g. 'Nov 10, 2026 8:14 PM'.
    Portable across platforms (no locale-specific strftime flags); returns the input
    unchanged when it is empty or unparseable, so rendering never fails on a bad value."""
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
    except (ValueError, TypeError):
        return str(iso)
    hour = dt.hour % 12 or 12
    meridiem = "AM" if dt.hour < 12 else "PM"
    return f"{dt.strftime('%b')} {dt.day}, {dt.year} {hour}:{dt.minute:02d} {meridiem}"


def _esc(value):
    return html.escape("" if value is None else str(value))


def render_html(report):
    """Render a validated report (HC-FIND-01 §7) as one self-contained HTML document."""
    mode = report.get("mode", "sandboxed")
    eid = report.get("engagement_id", "")
    window = report.get("window") or {}
    scope = report.get("scope_summary") or {}
    parts = [_head(eid), _header(eid, window, scope, mode)]

    if mode == "passive-only":
        parts.append(
            '<div class="banner">This run did not have continuously proven sandbox '
            'containment, so active probing stopped at the first failed check. No confirmed '
            'findings are shown.</div>')

    if report.get("method_summary"):
        parts.append(f'<p class="method">{_esc(report["method_summary"])}</p>')

    parts.append(_coverage(report.get("coverage_summary") or {}))
    parts.append(_findings(report.get("findings") or []))
    parts.append(_hardening(report.get("hardening_notes") or []))
    parts.append(
        f'<footer>Generated {_esc(am_pm(report.get("generated_at")))}</footer></body></html>')
    return "\n".join(parts)


def _head(eid):
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>Engagement {_esc(eid)}</title>\n<style>\n"
        ":root{color-scheme:light dark}\n"
        "body{font:16px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;"
        "max-width:60rem;margin:0 auto;padding:2rem 1rem;color:#1b1f24;background:#fff}\n"
        "h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.1rem;margin:2rem 0 .75rem;"
        "border-bottom:1px solid #d8dce1;padding-bottom:.3rem}\n"
        ".meta{color:#5b6470;font-size:.9rem;margin:0 0 1.25rem}\n"
        ".badge{display:inline-block;padding:.08rem .5rem;border-radius:1rem;color:#fff;"
        "font-size:.78rem;font-weight:600;vertical-align:middle}\n"
        ".banner{background:#fff4e5;border:1px solid #f0c38e;color:#8a5a00;padding:.8rem 1rem;"
        "border-radius:.5rem;margin:1rem 0}\n"
        ".method{color:#3a424c}\n"
        ".cov{background:#f6f7f9;border:1px solid #e3e7ec;border-radius:.5rem;padding:.6rem 1rem;"
        "display:flex;flex-wrap:wrap;gap:1.2rem;font-size:.9rem}\n"
        ".cov b{font-size:1.15rem;display:block}\n"
        ".card{background:#fbfcfd;border:1px solid #e3e7ec;border-left-width:4px;border-radius:.5rem;"
        "padding:1rem 1.15rem;margin:.9rem 0}\n"
        ".card h3{margin:0 0 .15rem;font-size:1.02rem}\n"
        ".card .meta{margin:.1rem 0 .6rem}\n"
        ".label{font-weight:600;color:#3a424c}\n"
        ".steps{color:#5b6470;font-size:.88rem;margin:.5rem 0 0;padding-left:1.1rem}\n"
        "footer{margin-top:2.5rem;color:#8a929b;font-size:.82rem}\n"
        # dark-mode overrides last, so source order lets them win over the base rules above
        "@media (prefers-color-scheme: dark){"
        "body{background:#15171a;color:#e6e8ea}"
        "h2{border-color:#2c3139}"
        ".cov,.card{background:#1e2126;border-color:#2c3139}"
        ".meta,.steps,.method{color:#9aa3ad}"
        ".label,.banner{color:#e6e8ea}"
        ".banner{background:#3a2e1a;border-color:#6b5324}"
        "footer{color:#79828c}}\n"
        "</style>\n</head>\n<body>")


def _header(eid, window, scope, mode):
    hosts = ", ".join(_esc(h) for h in (scope.get("in_scope_hosts") or [])) or "none"
    win = ""
    if window.get("start") or window.get("end"):
        win = f"{_esc(am_pm(window.get('start')))} to {_esc(am_pm(window.get('end')))} &middot; "
    badge = ('<span class="badge" style="background:#2f6f4e">sandboxed</span>'
             if mode == "sandboxed"
             else '<span class="badge" style="background:#8a5a00">passive-only</span>')
    return (f"<h1>Engagement {_esc(eid)} {badge}</h1>\n"
            f'<p class="meta">{win}in scope: {hosts} &middot; '
            f"max blast tier {_esc(scope.get('max_blast_tier'))}</p>")


def _coverage(cov):
    if not cov:
        return ""
    cells = "".join(f"<div><b>{_esc(v)}</b>{_esc(k.replace('_', ' '))}</div>"
                    for k, v in cov.items())
    return f'<h2>Coverage</h2>\n<div class="cov">{cells}</div>'


def _findings(findings):
    if not findings:
        return '<h2>Confirmed findings</h2>\n<p class="meta">No confirmed findings.</p>'
    cards = "".join(_finding_card(f) for f in findings)
    return f"<h2>Confirmed findings ({len(findings)})</h2>\n{cards}"


def _finding_card(f):
    cvss = f.get("cvss") or {}
    band = (cvss.get("band") or "none").lower()
    color = _BANDS.get(band, _BANDS["none"])
    score = cvss.get("score")
    sev = f'<span class="badge" style="background:{color}">{_esc(band)}'
    sev += f' {_esc(score)}</span>' if score is not None else "</span>"
    cwe = ", ".join(_esc(c) for c in (f.get("cwe") or [])) or "n/a"
    rows = [
        ("Impact", f.get("impact")),
        ("Remediation", f.get("remediation")),
        ("CWE", cwe),
        ("Found by", f.get("found_by")),
        ("Verified by", f.get("verified_by")),
    ]
    body = "".join(f'<div><span class="label">{lab}:</span> {_esc(val)}</div>'
                   for lab, val in rows)
    steps = ""
    if f.get("repro"):
        items = "".join(f"<li>{_esc(s)}</li>" for s in f["repro"])
        steps = f'<ol class="steps">{items}</ol>'
    return (f'<div class="card" style="border-left-color:{color}">'
            f'<h3>{_esc(f.get("technique_id"))} {sev}</h3>'
            f'<p class="meta">on {_esc(f.get("asset"))}</p>'
            f"{body}{steps}</div>")


def _hardening(notes):
    if not notes:
        return ""
    cards = "".join(
        f'<div class="card">'
        f'<h3>{_esc(n.get("technique_id"))}</h3>'
        f'<p class="meta">on {_esc(n.get("asset"))}</p>'
        f'<div>{_esc(n.get("note") or n.get("impact"))}</div></div>'
        for n in notes)
    return (f"<h2>Hardening notes ({len(notes)})</h2>\n"
            '<p class="meta">Defense-in-depth gaps with no demonstrated impact; no severity.</p>\n'
            f"{cards}")
