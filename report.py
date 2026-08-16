#!/usr/bin/env python3
"""
Generates a modern executive HTML vulnerability report.
Input:  resultado_cruzamento.csv + expanded.csv
Output: vulnerability_report.html
"""
import argparse
import csv
import html
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def _has_flag(cve: dict[str, Any], key: str) -> bool:
    """Case-insensitive truthy check for a CSV boolean column."""
    return str(cve.get(key, "")).lower() == "true"


def _exploit_cell(cve: dict[str, Any]) -> str:
    """Render the Exploit cell as 3 independent signal chips: V(erified),
    P(ublished), K(it). Each chip is lit (colored) when its CSV flag is
    true and dimmed otherwise, with a title/aria-label explaining the
    signal — the meaning must not depend on hover alone (see the
    `.expl-legend` block rendered once near the top of the page)."""
    signals = [
        ("v", "V", _has_flag(cve, "hasVerifiedExploit"), "Verified exploit exists"),
        ("p", "P", _has_flag(cve, "hasPublishedExploit"), "Published exploit exists"),
        ("k", "K", _has_flag(cve, "isInExploitKit"), "Included in an exploit kit"),
    ]
    chips = "".join(
        f'<span class="expl-chip {"on-" + code if on else "off"}" '
        f'title="{html.escape(label)}" '
        f'aria-label="{html.escape(label)}: {"yes" if on else "no"}">'
        f'{letter}</span>'
        for code, letter, on, label in signals
    )
    return f'<td class="expl-cell">{chips}</td>'


def _cve_row(cve: dict[str, Any]) -> str:
    """
    Render a `<tr>` for one CVE with the data-* attributes needed by the
    client-side filters (task #18). Attributes are lowercase so JS can match
    them directly against the filter values without normalization.
    `data-v`/`data-p`/`data-k` expose the three exploit signals
    independently so neither the UI nor the filters collapse them into
    one icon.
    """
    sev   = cve.get("severity", "") or ""
    patch = str(cve.get("patchable", "")).lower()
    pkg   = cve.get("packageName", "") or ""
    patch_icon = "✅" if patch == "true" else ("❌" if patch == "false" else "—")
    v = "1" if _has_flag(cve, "hasVerifiedExploit") else "0"
    p = "1" if _has_flag(cve, "hasPublishedExploit") else "0"
    k = "1" if _has_flag(cve, "isInExploitKit") else "0"
    return (
        f'<tr data-sev="{html.escape(sev, quote=True)}" '
        f'data-patch="{html.escape(patch, quote=True)}" '
        f'data-v="{v}" data-p="{p}" data-k="{k}">'
        f'<td class="mono">{html.escape(cve["id"])}</td>'
        f'<td>{dot(sev)}{html.escape(sev)}</td>'
        f'<td>{badge(cve["score"])}</td>'
        f'<td class="mono" style="font-size:.8em;color:#475569">{html.escape(pkg)}</td>'
        f'{_version_cell(cve)}'
        f'<td style="font-size:.8em;text-align:center">{patch_icon}</td>'
        f'{_fix_status_cell(cve)}'
        f'{_age_cell(cve)}'
        f'{_exploit_cell(cve)}'
        f'</tr>'
    )


def _version_cell(cve: dict[str, Any]) -> str:
    """Render the Current → Fixed cell with a copy-to-clipboard button.

    The button copies `<package> <current> → <fixed>` — the exact snippet a dev
    needs to paste into a Dockerfile pin, `requirements.txt`, or `pom.xml`.
    Values are HTML-escaped because packageName may contain characters that
    would otherwise break the data-copy attribute (e.g. `<`, `>`, `"`).
    """
    current = cve.get("currentVersion", "") or "—"
    fixed   = cve.get("fixedVersion", "") or "—"
    pkg     = cve.get("packageName", "") or ""
    display = f"{current} → {fixed}"
    payload = f"{pkg} {current} → {fixed}".strip()
    payload_attr = html.escape(payload, quote=True)
    return (
        f'<td style="font-size:.8em" class="mono">'
        f'<span>{html.escape(display)}</span>'
        f'<button class="copy-btn" data-copy="{payload_attr}" onclick="cpy(this)" '
        f'title="Copy `{payload_attr}`">⧉</button>'
        f'</td>'
    )


def _cve_table_head() -> str:
    """Shared `<thead>` for both the image-view and namespace-view CVE
    tables — keeps the two render paths from drifting out of sync when
    columns are added or reordered (PR-UX-3 Task 4)."""
    cols = ["CVE ID", "Severity", "Score", "Package", "Current → Fixed",
            "Patch", "Fix Status", "Age (days)", "Exploit"]
    ths = "".join(f"<th>{c}</th>" for c in cols)
    return f"<thead><tr>{ths}</tr></thead>"


def _fix_status_cell(cve: dict[str, Any]) -> str:
    """Render the Fix Status cell, defaulting to em-dash when absent.
    Value comes straight from Defender's `fixStatus` field (already in
    the CSV, previously loaded but never surfaced in the report)."""
    value = html.escape(str(cve.get("fixStatus", "") or "—"))
    return f'<td style="font-size:.8em;text-align:center">{value}</td>'


def _age_cell(cve: dict[str, Any]) -> str:
    """Render the CVE age-in-days cell, defaulting to em-dash when absent.
    `cveAgeDays="0"` is a real value (found today), not a missing one —
    only an empty/whitespace string counts as missing so freshly-published
    CVEs are visibly distinguished from ones we have no age data for."""
    age_raw = str(cve.get("cveAgeDays", "") or "").strip()
    value = html.escape(age_raw) if age_raw else "—"
    return f'<td style="font-size:.8em;text-align:center">{value}</td>'


def _new_cve_agg() -> dict[str, Any]:
    """defaultdict factory — explicit type keeps pyright happy about
    heterogeneous values (int/float/list) stored under the same dict."""
    return {"count": 0, "max": 0.0, "workloads": []}


def _is_weaponized(cve: dict[str, Any]) -> bool:
    """True if the CVE has any exploit signal (verified, published, or in-kit)."""
    return any(_has_flag(cve, k) for k in
               ("hasVerifiedExploit", "hasPublishedExploit", "isInExploitKit"))


def build_image_view(namespaces: dict) -> list[dict[str, Any]]:
    """
    Transform the namespace-oriented structure into an image-oriented view:
    one entry per unique (repository, tag, digest) with the workloads that
    run it and the deduplicated CVE list. Ordered by max CVSS score desc.

    Rationale (task #15): devs remediate at the image layer, not the workload
    layer — if `myapp/backend:v1.2` runs in three namespaces, they patch the
    image once. Grouping by image collapses the noise.
    """
    images: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ns_name, ws in namespaces.items():
        for (_wtype, _wname), w in ws.items():
            key = (w["repo"], w.get("tag", ""), w["digest"])
            entry = images.setdefault(key, {
                "repo":       w["repo"],
                "tag":        w.get("tag", ""),
                "digest":     w["digest"],
                "workloads":  [],
                "cves":       [],
                "max_score":  0.0,
                "weaponized_count": 0,
            })
            entry["workloads"].append((ns_name, w["name"], w["type"]))
            seen = {c["id"] for c in entry["cves"]}
            for c in w["cves"]:
                if c["id"] in seen:
                    continue
                entry["cves"].append(c)
                seen.add(c["id"])
                if c["score"] > entry["max_score"]:
                    entry["max_score"] = c["score"]
                if _is_weaponized(c):
                    entry["weaponized_count"] += 1
    return sorted(images.values(), key=lambda x: -x["max_score"])

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
SUMMARY_CSV = os.path.join(SCRIPT_DIR, "resultado_cruzamento.csv")
EXPANDED_CSV= os.path.join(SCRIPT_DIR, "expanded.csv")
OUTPUT_HTML = os.path.join(SCRIPT_DIR, "vulnerability_report.html")

def svg(paths, size=16, color="currentColor", sw=1.8):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
            f'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="{sw}" '
            f'stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">'
            f'{paths}</svg>')

IC = {
    "shield":   '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "alert":    '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/>',
    "namespace":'<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
    "workload": '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
    "cve":      '<circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>',
    "entries":  '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "critical": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "chevron":  '<polyline points="6 9 12 15 18 9"/>',
    "lock":     '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "patch":    '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/>',
    "network":  '<rect x="2" y="2" width="8" height="8"/><rect x="14" y="2" width="8" height="8"/><rect x="14" y="14" width="8" height="8"/><rect x="2" y="14" width="8" height="8"/>',
    "zap":      '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "target":   '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
}

def ic(name, size=15, color="currentColor"):
    return svg(IC[name], size=size, color=color)

def sev_class(score):
    s = float(score)
    if s == 10.0:
        return "s-max"
    if s >= 9.5:
        return "s-crit"
    if s >= 9.0:
        return "s-high"
    return "s-med"

def badge(score):
    return f'<span class="badge {sev_class(score)}">{score}</span>'

def dot(severity):
    c = {"Critical":"#EF4444","High":"#F97316","Medium":"#EAB308","Low":"#22C55E"}.get(severity,"#94A3B8")
    return f'<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:{c};margin-right:5px;vertical-align:middle"></span>'

def wbadge(wtype):
    meta = {
        "Deployment":       ("dep",   "#DBEAFE","#1D4ED8"),
        "DeploymentConfig": ("dconf", "#EDE9FE","#6D28D9"),
        "Job":              ("job",   "#FEF3C7","#92400E"),
        "StatefulSet":      ("ss",    "#DCFCE7","#15803D"),
        "Pod":              ("pod",   "#FCE7F3","#9D174D"),
    }
    cls, _bg, _fg = meta.get(wtype, ("other","#F1F5F9","#475569"))
    return f'<span class="wb wb-{cls}">{wtype}</span>'

def load_data(summary_path: str | os.PathLike | None = None,
              expanded_path: str | os.PathLike | None = None):
    summary_path = summary_path or SUMMARY_CSV
    expanded_path = expanded_path or EXPANDED_CSV
    ns = defaultdict(dict)
    with open(summary_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            key = (r["PARENT_TYPE"], r["PARENT_NAME"])
            ns[r["NAMESPACE"]][key] = {
                "type": r["PARENT_TYPE"], "name": r["PARENT_NAME"],
                "repo": r["REPOSITORY"],  "digest": r["DIGEST"],
                            "tag":  r.get("TAG", ""),
                            "cve_count": int(r["CVE_COUNT"]),
                            "max_score": float(r["CVSS_SCORE"]), "cves": [],
                        }
    with open(expanded_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            key = (r["PARENT_TYPE"], r["PARENT_NAME"])
            if r["NAMESPACE"] in ns and key in ns[r["NAMESPACE"]]:
                ns[r["NAMESPACE"]][key]["cves"].append({
                    "id":              r["CVE_ID"],
                    "severity":        r["SEVERITY"],
                    "score":           float(r.get("CVSS_SCORE", 0) or 0),
                    "packageName":     r.get("PACKAGE_NAME", ""),
                    "currentVersion":  r.get("CURRENT_VERSION", ""),
                    "fixedVersion":    r.get("FIXED_VERSION", ""),
                    "patchable":       r.get("PATCHABLE", ""),
                    "fixStatus":       r.get("FIX_STATUS", ""),
                    "isInExploitKit":  r.get("IS_IN_EXPLOIT_KIT", "false"),
                    "hasPublishedExploit": r.get("HAS_PUBLISHED_EXPLOIT", "false"),
                    "hasVerifiedExploit":  r.get("HAS_VERIFIED_EXPLOIT", "false"),
                    "cveAgeDays":      r.get("CVE_AGE_DAYS", ""),
                })
    return ns

def build_html(namespaces):
    """Render the vulnerability report as a single self-contained HTML string.

    Design (task #35 redesign): editorial data-driven aesthetic. Every pixel
    earns its place — devs land, filter, find their image, copy the fix. No
    synthetic scores, no marketing tone, no client branding.
    """
    now = datetime.now().strftime("%d %b %Y, %H:%M")

    all_w    = [(ns, k, w) for ns, ws in namespaces.items() for k, w in ws.items()]
    all_cves = [c for _, _, w in all_w for c in w["cves"]]

    cve_agg: defaultdict[str, dict[str, Any]] = defaultdict(_new_cve_agg)
    for ns_name, _, w in all_w:
        for c in w["cves"]:
            cve_agg[c["id"]]["count"] += 1
            cve_agg[c["id"]]["max"]    = max(cve_agg[c["id"]]["max"], c["score"])
            cve_agg[c["id"]]["workloads"].append((ns_name, w["name"], w["type"], w["repo"]))

    top_cves    = sorted(cve_agg.items(), key=lambda x: (-x[1]["max"], -x[1]["count"]))[:12]
    score10     = [(ns, w) for ns, _, w in all_w if w["max_score"] == 10.0]
    images_view = build_image_view(namespaces)

    total_images = len(images_view)
    total_w      = len(all_w)
    total_e      = len(all_cves)
    unique_cves  = len(cve_agg)
    s10_count    = len(score10)
    # Weaponized = any CVE entry with a known exploit (verified > published > kit).
    weap_count   = sum(1 for c in all_cves if _is_weaponized(c))

    # ── Alert bar ── only when there's something that demands action NOW.
    # This is the single "you cannot ignore this" element; kept sticky in CSS.
    alert_parts = []
    if s10_count > 0:
        alert_parts.append(f"{s10_count} workload{'s' if s10_count!=1 else ''} at CVSS 10.0")
    if weap_count > 0:
        alert_parts.append(f"{weap_count} weaponized CVE entr{'ies' if weap_count!=1 else 'y'}")
    alert_html = (
        f'<div class="alert-bar" role="alert">'
        f'<strong>Immediate action:</strong> {" · ".join(alert_parts)}'
        f'</div>'
        if alert_parts else ""
    )

    # ── Vulnerable Images cards ── primary dev-facing view, top-3 open ──
    image_cards = ""
    for i, img in enumerate(images_view):
        repo    = img["repo"]
        tag     = img.get("tag", "") or ""
        digest  = img["digest"]
        tag_present = tag not in ("N/A", "")
        full_ref = f"{repo}:{tag}@{digest}" if tag_present else f"{repo}@{digest}"
        full_ref_attr = html.escape(full_ref, quote=True)
        digest_short = digest[:24] + "..." if len(digest) > 24 else digest
        tag_html_span = (
            f'<span class="img-tag" title="tag: {html.escape(tag, quote=True)}">'
            f':{html.escape(tag)}</span>'
            if tag_present else
            '<span class="img-tag img-tag-missing" title="tag not recorded by scanner">:(no tag)</span>'
        )
        cve_count = len(img["cves"])
        weap = img["weaponized_count"]
        weap_pill = f'<span class="pill pill-red">{weap} weaponized</span>' if weap > 0 else ""
        runs_in = " ".join(
            f'<span class="run-chip"><span class="ns-tag">{html.escape(ns_name)}</span> / '
            f'<span style="font-weight:600">{html.escape(wname)}</span> {wbadge(wtype)}</span>'
            for ns_name, wname, wtype in sorted(img["workloads"])
        )
        cve_rows = "".join(_cve_row(c) for c in sorted(img["cves"], key=lambda x: -x["score"]))
        search_terms = " ".join([repo, tag] +
                                [ns for ns, _, _ in img["workloads"]] +
                                [wname for _, wname, _ in img["workloads"]])
        # Top 3 expanded by default — dev sees the worst without clicking.
        body_style = ' style="display:block"' if i < 3 else ''
        chev_style = ' style="transform:rotate(180deg)"' if i < 3 else ''
        image_cards += f'''
        <div class="card" data-search="{html.escape(search_terms.lower(), quote=True)}">
          <button class="card-btn" onclick="toggle(this)">
            <div class="card-left">
              <span class="img-ref mono">
                <span class="img-repo">{html.escape(repo)}</span>{tag_html_span}<span class="img-digest">@{digest_short}</span>
              </span>
              <button class="copy-btn copy-btn-ref" data-copy="{full_ref_attr}" onclick="cpy(this)" title="Copy {full_ref_attr}">⧉</button>
            </div>
            <div class="card-right">
              {badge(img["max_score"])}
              <span class="pill">{cve_count} CVE{"s" if cve_count != 1 else ""}</span>
              {weap_pill}
              <span class="chev"{chev_style}>{ic("chevron",15,"#94A3B8")}</span>
            </div>
          </button>
          <div class="card-body"{body_style}>
            <div class="runs-in"><strong>Runs in:</strong> {runs_in}</div>
            <table class="cve-tbl">
              {_cve_table_head()}
              <tbody>{cve_rows}</tbody>
            </table>
          </div>
        </div>'''

    # ── Namespace Detail ── SRE view, all collapsed ─────────────────────
    def _ns_total_cves(ns): return sum(w["cve_count"] for w in namespaces[ns].values())
    def _ns_max(ns):
        vals = [w["max_score"] for w in namespaces[ns].values()]
        return max(vals) if vals else 0.0

    ns_html = ""
    for ns_name in sorted(namespaces.keys(), key=lambda x: -_ns_total_cves(x)):
        ws = namespaces[ns_name]
        ns_score = _ns_max(ns_name)
        total_ns_cves = sum(w["cve_count"] for w in ws.values())

        wl_cards = ""
        for (wtype, wname), w in sorted(ws.items(), key=lambda x: -x[1]["max_score"]):
            digest_s = w["digest"][:24] + "..."
            cve_trs = "".join(_cve_row(c) for c in sorted(w["cves"], key=lambda x: -x["score"]))
            tag_span = (
                f'<span class="img-tag">:{html.escape(w["tag"])}</span>'
                if w.get("tag") and w["tag"] not in ("N/A", "") else ""
            )
            wl_cards += f'''
            <div class="wl-card">
              <div class="wl-hdr">
                <div class="wl-left">
                  <span class="wl-name">{html.escape(wname)}</span>
                  {wbadge(wtype)}
                  <span class="wl-cpill">{w["cve_count"]} CVE{"s" if w["cve_count"]>1 else ""}</span>
                </div>
                {badge(w["max_score"])}
              </div>
              <div class="wl-img">
                <span class="mono img-repo">{html.escape(w["repo"])}</span>{tag_span}<span class="digest-t">@{digest_s}</span>
              </div>
              <table class="cve-tbl">
                {_cve_table_head()}
                <tbody>{cve_trs}</tbody>
              </table>
            </div>'''

        ns_search = " ".join([ns_name] + [w["repo"] for w in ws.values()] +
                             [w["name"] for w in ws.values()])
        ns_html += f'''
        <div class="card" data-search="{html.escape(ns_search.lower(), quote=True)}">
          <button class="card-btn" onclick="toggle(this)">
            <div class="card-left">
              <span class="ns-name">{html.escape(ns_name)}</span>
              <span class="pill">{len(ws)} workload{"s" if len(ws)>1 else ""}</span>
              <span class="pill pill-y">{total_ns_cves} CVEs</span>
            </div>
            <div class="card-right">
              {badge(ns_score)}
              <span class="chev">{ic("chevron",15,"#94A3B8")}</span>
            </div>
          </button>
          <div class="card-body">{wl_cards}</div>
        </div>'''

    # ── Most Widespread CVEs ── reference table, tertiary ────────────────
    widespread_html = ""
    if top_cves:
        max_count = max(d["count"] for _, d in top_cves)
        cve_rows_html = "".join(
            f'<tr>'
            f'<td class="mono">{html.escape(cve_id)}</td>'
            f'<td>{badge(d["max"])}</td>'
            f'<td class="w-bar">'
            f'<div class="bar-wrap">'
            f'<div class="bar-fill" style="width:{int(d["count"] / max_count * 100)}%"></div>'
            f'<span class="bar-label">{d["count"]}</span>'
            f'</div>'
            f'</td>'
            f'</tr>'
            for cve_id, d in top_cves
        )
        widespread_html = f'''
        <div class="tbl-wrap">
          <table class="tbl-widespread">
            <thead><tr><th>CVE ID</th><th>Max Score</th><th>Workloads affected</th></tr></thead>
            <tbody>{cve_rows_html}</tbody>
          </table>
        </div>'''

    weap_cls = "kpi-num critical" if weap_count > 0 else "kpi-num"
    s10_cls  = "kpi-num critical" if s10_count > 0 else "kpi-num"

    css = """
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#FAFAF9; --surface:#FFFFFF; --border:#E7E5E4; --border-strong:#D6D3D1;
      --text:#1C1917; --text-2:#57534E; --text-3:#A8A29E; --accent:#059669;
      --critical:#DC2626; --high:#EA580C; --medium:#CA8A04; --low:#16A34A;
      --alert-bg:#FEE2E2; --alert-border:#FCA5A5; --alert-text:#7F1D1D;
    }
    body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.55;font-feature-settings:'cv11','ss01','ss03';-webkit-font-smoothing:antialiased}
    code,.mono{font-family:'JetBrains Mono','SF Mono',ui-monospace,Menlo,Monaco,'Cascadia Mono',monospace;font-size:.88em}
    .topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:0 32px;height:52px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:200}
    .brand{display:flex;align-items:center;gap:10px}
    .brand-mark{width:10px;height:10px;background:var(--accent);border-radius:2px}
    .brand-title{font-weight:700;font-size:.92em;color:var(--text);letter-spacing:-.01em}
    .topbar-date{font-size:.78em;color:var(--text-3);font-variant-numeric:tabular-nums}
    .alert-bar{background:var(--alert-bg);color:var(--alert-text);border-bottom:1px solid var(--alert-border);padding:10px 32px;font-size:.88em;position:sticky;top:52px;z-index:190}
    .alert-bar strong{font-weight:700;margin-right:6px}
    .container{max-width:1120px;margin:0 auto;padding:24px 24px 60px}
    .filters{position:sticky;top:52px;z-index:100;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-bottom:20px;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
    .alert-bar + .container .filters{top:calc(52px + 42px)}
    .filters label{font-size:.7em;color:var(--text-2);font-weight:600;display:flex;align-items:center;gap:6px;text-transform:uppercase;letter-spacing:.6px}
    .filters select,.filters input{font-family:inherit;font-size:.88em;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:5px 8px}
    .filters select:focus,.filters input:focus{outline:2px solid var(--accent);outline-offset:-1px;background:var(--surface)}
    .filters input[type="text"]{flex:1;min-width:220px}
    .f-clear{background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:5px 12px;font-size:.82em;color:var(--text-2);cursor:pointer;font-weight:600}
    .f-clear:hover{background:var(--surface);border-color:var(--border-strong)}
    .f-count{font-size:.75em;color:var(--text-3);margin-left:auto;font-weight:600;font-variant-numeric:tabular-nums}
    .kpi-strip{display:flex;flex-wrap:wrap;gap:0;border:1px solid var(--border);border-radius:8px;background:var(--surface);overflow:hidden;margin-bottom:32px}
    .kpi-item{flex:1;min-width:130px;padding:16px 20px;border-right:1px solid var(--border);display:flex;flex-direction:column;gap:2px}
    .kpi-item:last-child{border-right:0}
    .kpi-num{font-size:1.8em;font-weight:700;color:var(--text);line-height:1;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
    .kpi-num.critical{color:var(--critical)}
    .kpi-label{font-size:.7em;text-transform:uppercase;letter-spacing:.8px;color:var(--text-3);font-weight:600;margin-top:6px}
    .section-title{font-size:.72em;text-transform:uppercase;letter-spacing:1.2px;color:var(--text-2);font-weight:700;margin:36px 0 4px;display:flex;align-items:center;gap:10px}
    .section-title::after{content:'';flex:1;height:1px;background:var(--border)}
    .section-note{font-size:.82em;color:var(--text-3);margin-bottom:14px}
    .section-note code{background:var(--bg);color:var(--text-2);padding:1px 5px;border-radius:3px;font-size:.9em}
    .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:8px;overflow:hidden}
    .card-btn{width:100%;background:none;border:0;cursor:pointer;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:16px;color:inherit;text-align:left}
    .card-btn:hover{background:var(--bg)}
    .card-left{display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0;flex:1}
    .card-right{display:flex;align-items:center;gap:8px;flex-shrink:0}
    .card-body{display:none;padding:4px 16px 14px;border-top:1px solid var(--border)}
    .chev{transition:transform .18s;display:flex;color:var(--text-3)}
    .img-ref{display:inline-flex;align-items:baseline;gap:0;flex-wrap:wrap;min-width:0}
    .img-repo{color:var(--text);font-weight:600;font-size:.92em}
    .img-tag{display:inline-block;background:#DBEAFE;color:#1E40AF;font-weight:700;padding:1px 8px;border-radius:4px;margin:0 4px;font-size:.9em;letter-spacing:.2px}
    .img-tag-missing{background:var(--bg);color:var(--text-3);font-weight:500}
    .img-digest{color:var(--text-3);font-size:.8em;overflow:hidden;text-overflow:ellipsis}
    .digest-t{color:var(--text-3);font-size:.82em;margin-left:2px}
    .ns-name{font-weight:700;font-size:.92em;color:var(--text)}
    .pill{background:var(--bg);color:var(--text-2);border:1px solid var(--border);border-radius:20px;padding:1px 8px;font-size:.72em;font-weight:600;font-variant-numeric:tabular-nums}
    .pill-y{background:#FEF9C3;color:#854D0E;border-color:#FDE68A}
    .pill-red{background:#FEE2E2;color:#991B1B;border-color:#FCA5A5}
    .badge{display:inline-block;border-radius:20px;padding:2px 10px;font-size:.78em;font-weight:700;font-variant-numeric:tabular-nums}
    .s-max{background:#FEE2E2;color:#991B1B}
    .s-crit{background:#FED7AA;color:#9A3412}
    .s-high{background:#FEF3C7;color:#854D0E}
    .s-med{background:#D1FAE5;color:#166534}
    .wb{border-radius:4px;padding:1px 6px;font-size:.7em;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
    .wb-dep{background:#DBEAFE;color:#1E40AF}
    .wb-dconf{background:#EDE9FE;color:#5B21B6}
    .wb-job{background:#FEF3C7;color:#92400E}
    .wb-ss{background:#D1FAE5;color:#166534}
    .wb-pod{background:#FCE7F3;color:#9D174D}
    .wb-other{background:var(--bg);color:var(--text-2)}
    .wl-card{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px 14px;margin-top:10px}
    .wl-hdr{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:6px}
    .wl-left{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
    .wl-name{font-weight:700;font-size:.9em;color:var(--text)}
    .wl-cpill{background:#FED7AA;color:#9A3412;border-radius:20px;padding:1px 8px;font-size:.72em;font-weight:600}
    .wl-img{display:flex;align-items:baseline;gap:0;font-size:.85em;margin-bottom:10px;flex-wrap:wrap}
    .cve-tbl{width:100%;border-collapse:collapse;font-size:.85em;background:var(--surface);border-radius:5px;overflow:hidden}
    .cve-tbl thead th{padding:8px 10px;text-align:left;font-size:.68em;text-transform:uppercase;letter-spacing:.6px;color:var(--text-3);font-weight:700;background:var(--bg);border-bottom:1px solid var(--border)}
    .cve-tbl td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:middle}
    .cve-tbl tbody tr:last-child td{border-bottom:0}
    .cve-tbl tbody tr:hover{background:var(--bg)}
    .runs-in{font-size:.82em;color:var(--text-2);margin:10px 0;padding:8px 10px;background:var(--bg);border-radius:5px;line-height:1.8}
    .runs-in strong{color:var(--text);font-size:.88em;margin-right:6px;text-transform:uppercase;letter-spacing:.5px}
    .run-chip{display:inline-flex;align-items:center;gap:4px;background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:1px 8px;margin:2px 4px 2px 0;font-size:.9em}
    .ns-tag{color:var(--text-3);font-size:.9em}
    .copy-btn{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:1px 6px;margin-left:6px;cursor:pointer;color:var(--text-2);font-size:.9em;line-height:1;transition:all .1s}
    .copy-btn:hover{background:var(--bg);color:var(--text);border-color:var(--border-strong)}
    .copy-btn.ok{background:#D1FAE5;color:#166534;border-color:#6EE7B7}
    .copy-btn-ref{padding:2px 8px;font-size:.9em;margin-left:8px}
    .expl-cell{text-align:center;white-space:nowrap}
    .expl-chip{display:inline-block;width:16px;height:16px;line-height:16px;border-radius:3px;font-size:.68em;font-weight:700;margin:0 1px;color:#fff;cursor:help;text-align:center}
    .expl-chip.off{background:var(--border);color:var(--text-3)}
    .expl-chip.on-v{background:var(--critical)}
    .expl-chip.on-p{background:var(--high)}
    .expl-chip.on-k{background:var(--medium)}
    .expl-legend{font-size:.78em;color:var(--text-2);margin:0 0 20px;padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;display:flex;gap:16px;flex-wrap:wrap;align-items:center}
    .expl-legend strong{color:var(--text);font-size:.92em}
    .expl-legend .expl-chip{cursor:default}
    .tbl-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
    .tbl-widespread{width:100%;border-collapse:collapse;font-size:.9em}
    .tbl-widespread thead th{padding:10px 14px;text-align:left;font-size:.68em;text-transform:uppercase;letter-spacing:.6px;color:var(--text-3);font-weight:700;background:var(--bg);border-bottom:1px solid var(--border)}
    .tbl-widespread td{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:middle}
    .tbl-widespread tbody tr:last-child td{border-bottom:0}
    .w-bar{width:280px}
    .bar-wrap{display:flex;align-items:center;gap:8px}
    .bar-fill{height:6px;background:linear-gradient(90deg,var(--accent),#34D399);border-radius:3px;min-width:4px}
    .bar-label{font-size:.85em;color:var(--text-2);font-weight:600;font-variant-numeric:tabular-nums}
    .footer{text-align:center;color:var(--text-3);font-size:.72em;margin-top:40px;padding-bottom:16px;letter-spacing:.4px}
    @media(max-width:720px){.kpi-item{min-width:50%}.container{padding:16px 12px 40px}.topbar{padding:0 16px}}
    .tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:20px}
    .tab-btn{background:none;border:0;border-bottom:2px solid transparent;padding:10px 4px;margin-right:24px;font-family:inherit;font-size:.88em;font-weight:700;color:var(--text-3);cursor:pointer}
    .tab-btn:hover{color:var(--text-2)}
    .tab-btn.active{color:var(--text);border-bottom-color:var(--accent)}
    .tab-src{font-size:.72em;font-weight:600;background:var(--bg);border:1px solid var(--border);border-radius:20px;padding:0 7px;margin-left:6px;color:var(--text-3)}
    .tab-panel{display:none}
    .tab-panel.active{display:block}
    .src-tag{font-size:.68em;text-transform:none;letter-spacing:0;font-weight:600;color:var(--text-3);background:var(--bg);border:1px solid var(--border);border-radius:20px;padding:1px 9px;margin-left:8px;vertical-align:middle}
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Container Vulnerability Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet"/>
<style>{css}</style>
</head>
<body>
<header class="topbar">
  <div class="brand">
    <span class="brand-mark"></span>
    <span class="brand-title">Container Vulnerability Report</span>
  </div>
  <span class="topbar-date">{now}</span>
</header>
{alert_html}
<div class="container">
  <div class="filters" role="region" aria-label="Filters">
    <label>Severity
      <select id="fSev" onchange="applyFilters()">
        <option value="">All</option>
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
      </select>
    </label>
    <label>Patchable
      <select id="fPatch" onchange="applyFilters()">
        <option value="">All</option>
        <option value="true">Yes</option>
        <option value="false">No</option>
      </select>
    </label>
    <label>Exploit
      <select id="fExpl" onchange="applyFilters()">
        <option value="">All</option>
        <option value="any">Any exploit</option>
        <option value="v">Verified only</option>
        <option value="p">Published only</option>
        <option value="k">In kit only</option>
      </select>
    </label>
    <input type="text" id="fSearch" placeholder="Filter by namespace, repo, workload…" oninput="applyFilters()"/>
    <button class="f-clear" onclick="clearFilters()">Clear</button>
    <span class="f-count" id="fCount"></span>
  </div>

  <div class="kpi-strip">
    <div class="kpi-item"><span class="kpi-num">{total_images}</span><span class="kpi-label">Images</span></div>
    <div class="kpi-item"><span class="kpi-num">{total_w}</span><span class="kpi-label">Workloads</span></div>
    <div class="kpi-item"><span class="kpi-num">{unique_cves}</span><span class="kpi-label">Unique CVEs</span></div>
    <div class="kpi-item"><span class="kpi-num">{total_e}</span><span class="kpi-label">CVE entries</span></div>
    <div class="kpi-item"><span class="{s10_cls}">{s10_count}</span><span class="kpi-label">Score 10.0</span></div>
    <div class="kpi-item"><span class="{weap_cls}">{weap_count}</span><span class="kpi-label">Weaponized</span></div>
  </div>

  <div class="expl-legend" aria-label="Exploit signal legend">
    <strong>Exploit signals:</strong>
    <span><span class="expl-chip on-v">V</span> Verified exploit exists</span>
    <span><span class="expl-chip on-p">P</span> Published exploit exists</span>
    <span><span class="expl-chip on-k">K</span> Included in an exploit kit</span>
  </div>

  <div class="tabs" role="tablist" aria-label="Report view">
    <button class="tab-btn active" id="tabbtn-images" role="tab" aria-selected="true"
            aria-controls="tab-images" onclick="switchTab('images')">
      Images <span class="tab-src">ACR</span>
    </button>
    <button class="tab-btn" id="tabbtn-cluster" role="tab" aria-selected="false"
            aria-controls="tab-cluster" onclick="switchTab('cluster')">
      Cluster <span class="tab-src">OpenShift</span>
    </button>
  </div>

  <div class="tab-panel active" id="tab-images" role="tabpanel" aria-labelledby="tabbtn-images">
    <h2 class="section-title">Vulnerable Images <span class="src-tag">Azure Container Registry</span></h2>
    <p class="section-note">Grouped by <code>repo:tag@digest</code>. Sorted by max CVSS descending. Top {min(3, total_images)} expanded by default.</p>
    {image_cards}
  </div>

  <div class="tab-panel" id="tab-cluster" role="tabpanel" aria-labelledby="tabbtn-cluster">
    <h2 class="section-title">Namespace Detail <span class="src-tag">OpenShift Cluster (Runtime)</span></h2>
    <p class="section-note">Same findings organized by OpenShift namespace and workload. Sorted by CVE count.</p>
    {ns_html}
  </div>

  <h2 class="section-title">Most Widespread CVEs</h2>
  <p class="section-note">Reference view — CVEs sorted by number of workloads they affect.</p>
  {widespread_html}

  <div class="footer">Confidential · Internal Use Only · Generated {now}</div>
</div>
<script>
function toggle(b){{var d=b.nextElementSibling;var o=d.style.display==='block';d.style.display=o?'none':'block';var c=b.querySelector('.chev');if(c)c.style.transform=o?'':'rotate(180deg)';}}
function cpy(btn){{event.stopPropagation();var t=btn.dataset.copy||'';if(navigator.clipboard){{navigator.clipboard.writeText(t).then(function(){{var o=btn.textContent;btn.textContent='✓';btn.classList.add('ok');setTimeout(function(){{btn.textContent=o;btn.classList.remove('ok');}},900);}});}}}}
function switchTab(name){{
  document.querySelectorAll('.tab-panel').forEach(function(p){{p.classList.toggle('active',p.id==='tab-'+name);}});
  document.querySelectorAll('.tab-btn').forEach(function(b){{
    var on=b.id==='tabbtn-'+name;
    b.classList.toggle('active',on);
    b.setAttribute('aria-selected',on?'true':'false');
  }});
  applyFilters();
}}
function applyFilters(){{
  var sev=document.getElementById('fSev').value;
  var patch=document.getElementById('fPatch').value;
  var expl=document.getElementById('fExpl').value;
  var search=document.getElementById('fSearch').value.toLowerCase().trim();
  var visibleCards=0;
  document.querySelectorAll('tr[data-sev]').forEach(function(row){{
    var ok=true;
    if(sev&&row.dataset.sev!==sev)ok=false;
    if(patch&&row.dataset.patch!==patch)ok=false;
    if(expl==='any'&&!(row.dataset.v==='1'||row.dataset.p==='1'||row.dataset.k==='1'))ok=false;
    if(expl==='v'&&row.dataset.v!=='1')ok=false;
    if(expl==='p'&&row.dataset.p!=='1')ok=false;
    if(expl==='k'&&row.dataset.k!=='1')ok=false;
    row.style.display=ok?'':'none';
  }});
  document.querySelectorAll('.card').forEach(function(card){{
    var s=card.dataset.search||'';
    var searchOk=!search||s.indexOf(search)!==-1;
    var totalRows=card.querySelectorAll('tr[data-sev]').length;
    var vis=card.querySelectorAll('tr[data-sev]:not([style*="none"])').length;
    var hasContent=(totalRows===0)||(vis>0);
    var show=searchOk&&hasContent;
    card.style.display=show?'':'none';
    if(show)visibleCards++;
  }});
  var c=document.getElementById('fCount');
  if(c)c.textContent=visibleCards+' cards visible';
}}
function clearFilters(){{
  document.getElementById('fSev').value='';
  document.getElementById('fPatch').value='';
  document.getElementById('fExpl').value='';
  document.getElementById('fSearch').value='';
  applyFilters();
}}
document.addEventListener('DOMContentLoaded',applyFilters);
</script>
</body>
</html>"""
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a modern executive HTML vulnerability report.",
    )
    parser.add_argument("--summary", "-s", default=SUMMARY_CSV,
                        help=f"Grouped cross-reference CSV (default: {SUMMARY_CSV})")
    parser.add_argument("--expanded", "-e", default=EXPANDED_CSV,
                        help=f"Expanded per-CVE CSV (default: {EXPANDED_CSV})")
    parser.add_argument("--output", "-o", default=OUTPUT_HTML,
                        help=f"Output HTML path (default: {OUTPUT_HTML})")
    args = parser.parse_args()

    for path, label in [(args.summary, "summary"), (args.expanded, "expanded")]:
        if not Path(path).exists():
            print(f"Error: {label} CSV not found: {path}", file=sys.stderr)
            return 1

    print("Loading data...")
    ns = load_data(args.summary, args.expanded)
    print(f"  -> {len(ns)} namespaces, {sum(len(v) for v in ns.values())} workloads")
    print("Generating report...")
    html = build_html(ns)
    Path(args.output).write_text(html, encoding="utf-8")
    print(f"  -> Saved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
