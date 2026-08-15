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


def _exploit_icon(cve: dict[str, Any]) -> str:
    """🔴 verified > 🟠 published > 🟡 in-kit > — none."""
    if str(cve.get("hasVerifiedExploit", "")).lower() == "true":
        return "🔴"
    if str(cve.get("hasPublishedExploit", "")).lower() == "true":
        return "🟠"
    if str(cve.get("isInExploitKit", "")).lower() == "true":
        return "🟡"
    return "—"


def _cve_row(cve: dict[str, Any]) -> str:
    """
    Render a `<tr>` for one CVE with the data-* attributes needed by the
    client-side filters (task #18). Attributes are lowercase so JS can match
    them directly against the filter values without normalization.
    """
    sev   = cve.get("severity", "") or ""
    patch = str(cve.get("patchable", "")).lower()
    expl  = "1" if _is_weaponized(cve) else "0"
    pkg   = cve.get("packageName", "") or ""
    patch_icon = "✅" if patch == "true" else ("❌" if patch == "false" else "—")
    return (
        f'<tr data-sev="{html.escape(sev, quote=True)}" '
        f'data-patch="{html.escape(patch, quote=True)}" '
        f'data-expl="{expl}">'
        f'<td class="mono">{html.escape(cve["id"])}</td>'
        f'<td>{dot(sev)}{html.escape(sev)}</td>'
        f'<td>{badge(cve["score"])}</td>'
        f'<td class="mono" style="font-size:.8em;color:#475569">{html.escape(pkg)}</td>'
        f'{_version_cell(cve)}'
        f'<td style="font-size:.8em;text-align:center">{patch_icon}</td>'
        f'<td style="font-size:.8em;text-align:center">{_exploit_icon(cve)}</td>'
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


def _new_cve_agg() -> dict[str, Any]:
    """defaultdict factory — explicit type keeps pyright happy about
    heterogeneous values (int/float/list) stored under the same dict."""
    return {"count": 0, "max": 0.0, "workloads": []}


def _is_weaponized(cve: dict[str, Any]) -> bool:
    """True if the CVE has any exploit signal (verified, published, or in-kit)."""
    for flag in ("hasVerifiedExploit", "hasPublishedExploit", "isInExploitKit"):
        if str(cve.get(flag, "")).lower() == "true":
            return True
    return False


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
    now = datetime.now().strftime("%d %b %Y, %H:%M")

    all_w    = [(ns, k, w) for ns, ws in namespaces.items() for k, w in ws.items()]
    all_cves = [c for _, _, w in all_w for c in w["cves"]]

    cve_agg: defaultdict[str, dict[str, Any]] = defaultdict(_new_cve_agg)
    for ns_name, _, w in all_w:
        for c in w["cves"]:
            cve_agg[c["id"]]["count"] += 1
            cve_agg[c["id"]]["max"]    = max(cve_agg[c["id"]]["max"], c["score"])
            cve_agg[c["id"]]["workloads"].append((ns_name, w["name"], w["type"], w["repo"]))

    top_cves     = sorted(cve_agg.items(), key=lambda x: (-x[1]["max"], -x[1]["count"]))[:12]
    score10      = [(ns, w) for ns, _, w in all_w if w["max_score"] == 10.0]
    top_workloads= sorted(all_w, key=lambda x: -x[2]["max_score"])[:5]

    total_ns       = len(namespaces)
    total_w        = len(all_w)
    total_e        = len(all_cves)
    unique_cves    = len(cve_agg)
    s10_count      = len(score10)
    # Weaponized = any CVE entry with a known exploit (verified > published > kit).
    # Counted at the entry level (one workload × one CVE) so operators see the
    # concrete exposure, not just the unique CVE count.
    weap_count     = sum(1 for c in all_cves if _is_weaponized(c))

    # ── Cluster Health Score (0–100) ─────────────────────────────────────────
    # Four weighted components, each scored 0–100 (higher = healthier):
    #
    #  A. Severity     (40%) — average CVSS of all entries, penalised non-linearly
    #  B. Blast radius (25%) — fraction of workloads carrying at least one CVE ≥9.0
    #  C. CVE density  (20%) — critical CVEs (≥9.8) per workload
    #  D. Exposure     (15%) — critical service namespaces affected (SSO, ingress…)
    #
    # Extra penalty applied after weighting:
    #  • Each CVE ≥9.8 affecting >20 workloads → −2 pts (max −10)
    #  • Each CVSS-10.0 workload beyond the first → −1 pt  (max −5)

    CRITICAL_NS_KW = ["sso", "rhsso", "keycloak", "auth", "ingress", "gateway",
                      "cert-manager", "vault", "iam", "ldap"]

    cvss_vals   = [c["score"] for c in all_cves] or [0]
    avg_cvss    = sum(cvss_vals) / len(cvss_vals)
    # A — severity: avg CVSS 9.5+ → ~0; 7.0 → ~50; 5.0 → ~100
    comp_sev    = max(0.0, min(100.0, (10.0 - avg_cvss) / 5.0 * 100))

    # B — blast radius: % of workloads with any CVE
    affected_wl = len(set((ns, w["name"]) for ns, _, w in all_w if w["cves"]))
    comp_blast  = max(0.0, 100.0 - (affected_wl / max(total_w, 1)) * 100)

    # C — CVE density: critical CVEs (≥9.8) per workload; 5+ per wl → 0
    crit_entries = sum(1 for c in all_cves if c["score"] >= 9.8)
    crit_density = crit_entries / max(total_w, 1)
    comp_density = max(0.0, 100.0 - crit_density * 20)

    # D — critical namespace exposure: −25 pts per critical NS affected
    hit_ns = [ns for ns in namespaces if any(k in ns.lower() for k in CRITICAL_NS_KW)]
    comp_exposure = max(0.0, 100.0 - len(hit_ns) * 25)

    raw_health = (comp_sev * 0.40 + comp_blast * 0.25 +
                  comp_density * 0.20 + comp_exposure * 0.15)

    # Extra penalties
    extra_pen = 0
    for _, d in cve_agg.items():
        if d["max"] >= 9.8 and d["count"] > 20:
            extra_pen += 2
    extra_pen = min(extra_pen, 10)
    extra_pen += min(max(s10_count - 1, 0), 5)

    health_score_raw = max(0, round(raw_health - extra_pen))
    # Floor at 5 so we never show a hard "0" — still signals critical
    health_score = max(5, health_score_raw)

    # Risk drivers (top 3 worst components only — no penalty row)
    risk_drivers = []
    driver_meta = {
        "Severity":     (comp_sev,      f"Avg CVSS {avg_cvss:.1f}"),
        "Blast Radius": (comp_blast,    f"{affected_wl}/{total_w} workloads affected"),
        "CVE Density":  (comp_density,  f"{crit_entries} critical CVE entries"),
        "Exposure":     (comp_exposure, f"{len(hit_ns)} critical service{'s' if len(hit_ns)!=1 else ''} exposed"),
    }
    for name, (val, detail) in sorted(driver_meta.items(), key=lambda x: x[1][0])[:3]:
        risk_drivers.append((name, round(val), detail))

    # 1-line insight: pick the single worst driver
    worst_driver = risk_drivers[0][0] if risk_drivers else "Severity"
    insight_map = {
        "Severity":     f"Average CVSS of {avg_cvss:.1f} across all entries indicates near-maximum exploitability.",
        "Blast Radius": f"All {affected_wl} workloads carry active CVEs — full cluster exposure with no clean baseline.",
        "CVE Density":  f"{crit_entries} critical CVE entries across {total_w} workloads require immediate image rebuilds.",
        "Exposure":     f"Critical services ({', '.join(hit_ns[:2])}) are affected, raising the risk of cascading impact.",
    }
    health_insight = insight_map.get(worst_driver, "")

    if health_score <= 40:
        health_color, health_label = "#DC2626", "Critical"
    elif health_score <= 70:
        health_color, health_label = "#F97316", "At Risk"
    else:
        health_color, health_label = "#059669", "Healthy"

    def ns_max(ns): return max(w["max_score"] for w in namespaces[ns].values())

    # Critical alert
    alert_items = "".join(
        f'<div class="al-item">'
        f'<span class="al-ns">{ns_name}</span><span class="al-sep">/</span>'
        f'<span class="al-name">{w["name"]}</span>'
        f'{wbadge(w["type"])}{badge(w["max_score"])}'
        f'</div>'
        for ns_name, w in sorted(score10, key=lambda x: x[0])
    )
    alert_html = f'''
    <div class="crit-alert">
      <div class="crit-hdr">{ic("alert",18,"#991B1B")} CVSS 10.0 — Maximum Severity — Immediate Action Required</div>
      <div class="al-grid">{alert_items}</div>
    </div>''' if score10 else ""

    # Top CVEs accordion
    max_count = max(d["count"] for _, d in top_cves) if top_cves else 1
    cve_accordion = ""
    for i, (cve_id, d) in enumerate(top_cves):
        bar = int(d["count"] / max_count * 100)
        wl_rows = "".join(
            f'<tr>'
            f'<td><span class="ns-tag">{ns_name}</span></td>'
            f'<td><span class="wl-name" style="font-size:.85em">{wname}</span> {wbadge(wtype)}</td>'
            f'<td class="mono" style="font-size:.8em;color:#64748B">{repo}</td>'
            f'</tr>'
            for ns_name, wname, wtype, repo in sorted(d["workloads"], key=lambda x: x[0])
        )
        cve_accordion += f'''
        <div class="ns-card">
          <button class="ns-btn" onclick="toggle(this)">
            <div class="ns-left">
              <span class="rank" style="font-size:.9em">{i+1:02d}</span>
              <span class="mono" style="font-size:.92em;color:#1E293B;font-weight:600">{cve_id}</span>
              {badge(d["max"])}
            </div>
            <div class="ns-right">
              <div class="barw" style="width:140px">
                <div class="barf" style="width:{bar}%"></div>
                <span class="barl">{d["count"]} workload{"s" if d["count"]>1 else ""}</span>
              </div>
              <span class="chev">{ic("chevron",15,"#94A3B8")}</span>
            </div>
          </button>
          <div class="ns-body">
            <table class="cve-tbl" style="margin-top:8px">
              <thead><tr><th>Namespace</th><th>Workload</th><th>Image</th></tr></thead>
              <tbody>{wl_rows}</tbody>
            </table>
          </div>
        </div>'''

    # Namespace accordion
    # ── Vulnerable Images view — one card per repo:tag@digest ──────────────
    # Renders BEFORE the Namespace view so devs land on the layer they need
    # to fix. Same collapsible pattern, so no extra JS.
    image_cards = ""
    for img in build_image_view(namespaces):
        digest_short = img["digest"][:24] + "..." if len(img["digest"]) > 24 else img["digest"]
        tag_html = (
            f'<span style="font-size:.85em;color:#0EA5E9;font-weight:600">:{img["tag"]}</span>'
            if img.get("tag") and img["tag"] not in ("N/A", "") else ""
        )
        cve_count = len(img["cves"])
        weap = img["weaponized_count"]
        weap_pill = (
            f'<span class="pill pill-red">{weap} weaponized</span>' if weap > 0 else ""
        )
        runs_in = " ".join(
            f'<span class="run-chip"><span class="ns-tag">{ns_name}</span> / '
            f'<span style="font-weight:600">{wname}</span> {wbadge(wtype)}</span>'
            for ns_name, wname, wtype in sorted(img["workloads"])
        )
        cve_rows = "".join(
            _cve_row(c) for c in sorted(img["cves"], key=lambda x: -x["score"])
        )
        # data-search: everything the free-text filter should match on
        search_terms = " ".join([img["repo"], img.get("tag", "") or ""] +
                                [ns for ns, _, _ in img["workloads"]] +
                                [wname for _, wname, _ in img["workloads"]])
        image_cards += f'''
        <div class="ns-card" data-search="{html.escape(search_terms.lower(), quote=True)}">
          <button class="ns-btn" onclick="toggle(this)">
            <div class="ns-left">
              <span class="mono" style="font-weight:600;color:#0F172A">{img["repo"]}</span>
              {tag_html}
              <span class="digest-t">@ {digest_short}</span>
            </div>
            <div class="ns-right">
              {badge(img["max_score"])}
              <span class="pill">{cve_count} CVE{"s" if cve_count != 1 else ""}</span>
              {weap_pill}
              <span class="chev">{ic("chevron",15,"#94A3B8")}</span>
            </div>
          </button>
          <div class="ns-body">
            <div class="runs-in"><strong>Runs in:</strong> {runs_in}</div>
            <table class="cve-tbl" style="margin-top:8px">
              <thead><tr><th>CVE ID</th><th>Severity</th><th>Score</th><th>Package</th><th>Current → Fixed</th><th>Patch</th><th>Exploit</th></tr></thead>
              <tbody>{cve_rows}</tbody>
            </table>
          </div>
        </div>'''

    ns_html = ""
    def ns_total_cves(ns): return sum(w["cve_count"] for w in namespaces[ns].values())
    for ns_name in sorted(namespaces.keys(), key=lambda x: -ns_total_cves(x)):
        ws       = namespaces[ns_name]
        ns_score = ns_max(ns_name)
        total_ns_cves = sum(w["cve_count"] for w in ws.values())

        cards = ""
        for (wtype, wname), w in sorted(ws.items(), key=lambda x: -x[1]["max_score"]):
            digest_s = w["digest"][:24] + "..."
            cve_trs = "".join(
                _cve_row(c) for c in sorted(w["cves"], key=lambda x: -x["score"])
            )
            cards += f'''
            <div class="wl-card">
              <div class="wl-hdr">
                <div class="wl-left">
                  <span class="wl-name">{wname}</span>
                  {wbadge(wtype)}
                  <span class="wl-cpill">{w["cve_count"]} CVE{"s" if w["cve_count"]>1 else ""}</span>
                </div>
                {badge(w["max_score"])}
              </div>
              <div class="wl-img">
                {ic("namespace",13,"#94A3B8")}
                <span class="mono">{w["repo"]}</span>
                {f'<span style="font-size:.8em;color:#0EA5E9;font-weight:600">:{w["tag"]}</span>' if w.get("tag") and w["tag"] not in ("N/A","") else ""}
                <span class="digest-t">@ {digest_s}</span>
              </div>
              <table class="cve-tbl">
                <thead><tr><th>CVE ID</th><th>Severity</th><th>Score</th><th>Package</th><th>Current → Fixed</th><th>Patch</th><th>Exploit</th></tr></thead>
                <tbody>{cve_trs}</tbody>
              </table>
            </div>'''

        ns_search = " ".join([ns_name] + [w["repo"] for w in ws.values()] +
                             [w["name"] for w in ws.values()])
        ns_html += f'''
        <div class="ns-card" data-search="{html.escape(ns_search.lower(), quote=True)}">
          <button class="ns-btn" onclick="toggle(this)">
            <div class="ns-left">
              {ic("namespace",15,"#64748B")}
              <span class="ns-name">{ns_name}</span>
              <span class="pill">{len(ws)} workload{"s" if len(ws)>1 else ""}</span>
              <span class="pill pill-y">{total_ns_cves} CVEs</span>
            </div>
            <div class="ns-right">
              {badge(ns_score)}
              <span class="chev">{ic("chevron",15,"#94A3B8")}</span>
            </div>
          </button>
          <div class="ns-body">{cards}</div>
        </div>'''

    # Analysis
    top3_wl = "".join(
        f'<li><strong>{ns_name}/{w["name"]}</strong> ({w["type"]}) &mdash; '
        f'<code>{w["repo"]}</code> &mdash; {w["cve_count"]} CVE(s), max CVSS {w["max_score"]}. '
        f'<em>Rebuild from latest patched base image and redeploy immediately.</em></li>'
        for ns_name, _, w in top_workloads
    )
    top3_cves = "".join(
        f'<li><code>{cve}</code> &mdash; CVSS {d["max"]} &mdash; '
        f'affects <strong>{d["count"]}</strong> workload(s). '
        f'Widespread base image contamination &mdash; rebuild all images using this layer.</li>'
        for cve, d in top_cves[:5]
    )
    imm_targets = "".join(
        f'<li><strong>{ns_name}/{w["name"]}</strong> &mdash; <code>{w["repo"]}</code> &mdash; '
        f'Rebuild and redeploy within 24h. Isolate with NetworkPolicy until patched.</li>'
        for ns_name, w in sorted(score10, key=lambda x: (x[0], x[1]["name"]))
    ) or "<li><em>No workload currently at CVSS 10.0.</em></li>"

    # ── Derived helpers for "Attack Vectors" and "Next Actions" ────────────
    # Prior versions hard-coded namespace names (prd-fad, prd-airflow, ...).
    # Now we derive them so the analysis stays truthful for any input.
    score10_ns = sorted({ns for ns, _ in score10})  # namespaces with a CVSS-10
    top_ns_by_wl = sorted(
        ((ns, len(ws)) for ns, ws in namespaces.items()),
        key=lambda x: -x[1],
    )[:3]
    top_freq_cves = [cve for cve, _ in top_cves[:3]]

    def _fmt_ns_list(ns_list: list[str], sep: str = " or ") -> str:
        codes = [f"<code>{html.escape(n)}</code>" for n in ns_list[:3]]
        return sep.join(codes) if codes else "<em>none</em>"

    lateral_html = (
        f"Compromised pods in {_fmt_ns_list(score10_ns)} share the cluster SDN, "
        "enabling pivoting across namespaces."
        if score10_ns else
        "No CVSS 10.0 workloads detected in the current scan &mdash; lateral "
        "movement risk is limited to the top-severity images listed above."
    )
    # Identity provider bullet: only surface if a known identity-adjacent NS is affected.
    id_kws = ("sso", "rhsso", "keycloak", "auth", "iam", "ldap")
    id_ns_hits = [ns for ns in score10_ns if any(k in ns.lower() for k in id_kws)]
    identity_html = (
        f"{_fmt_ns_list(id_ns_hits, sep=', ')} exposes identity/SSO surfaces at "
        "CVSS 10.0. Compromise grants access to all dependent services."
        if id_ns_hits else
        "No identity/SSO namespaces at CVSS 10.0 &mdash; keep monitoring for regression."
    )
    imm_workloads_html = _fmt_ns_list(
        [f"{ns}/{w['name']}" for ns, w in score10[:4]], sep=", "
    ) if score10 else "<em>none pending immediately</em>"
    top_ns_html = ", ".join(
        f"<code>{html.escape(n)}</code> ({c})" for n, c in top_ns_by_wl
    ) if top_ns_by_wl else "<em>none</em>"
    top_freq_cves_html = ", ".join(
        f"<code>{html.escape(c)}</code>" for c in top_freq_cves
    ) if top_freq_cves else "<em>none</em>"

    analysis = f'''
    <div class="analysis">
      <div class="a-hdr">
        {ic("shield",22,"#059669")}
        <div><h2>Security Analysis &amp; Recommendations</h2>
        <p>Executive summary for platform and development teams &mdash; {now}</p></div>
      </div>
      <div class="a-grid">
        <div class="a-card a-red">
          <div class="a-title">{ic("zap",15,"#991B1B")} Immediate Action Required (CVSS 10.0)</div>
          <ul class="a-list">{imm_targets}</ul>
        </div>
        <div class="a-card">
          <div class="a-title">{ic("target",15,"#D97706")} Most Critical Workloads</div>
          <ul class="a-list">{top3_wl}</ul>
        </div>
        <div class="a-card">
          <div class="a-title">{ic("activity",15,"#7C3AED")} Highest-Risk CVEs by Exposure</div>
          <ul class="a-list">{top3_cves}</ul>
        </div>
        <div class="a-card">
          <div class="a-title">{ic("network",15,"#DC2626")} OpenShift-Specific Attack Vectors</div>
          <ul class="a-list">
            <li><strong>RCE via heap overflow</strong> &mdash; expat/libxml2 CVEs allow remote code execution. In OpenShift, this can escalate to host access if the pod runs as root.</li>
            <li><strong>Privilege escalation</strong> &mdash; CVE-2024-1597 (pgjdbc, CVSS 10.0) allows unauthenticated SQL injection that can execute OS commands via the service account.</li>
            <li><strong>Lateral movement</strong> &mdash; {lateral_html}</li>
            <li><strong>Identity provider compromise</strong> &mdash; {identity_html}</li>
            <li><strong>Supply chain risk</strong> &mdash; {unique_cves} unique CVEs across {total_w} workloads indicate widespread base image contamination.</li>
          </ul>
        </div>
        <div class="a-card a-green" style="grid-column:1/-1">
          <div class="a-title">{ic("patch",15,"#065F46")} Recommended Next Actions</div>
          <ol class="a-list">
            <li><strong>24h:</strong> Isolate and rebuild CVSS 10.0 workloads &mdash; {imm_workloads_html}.</li>
            <li><strong>48-72h:</strong> Rebuild images affected by top-frequency CVEs ({top_freq_cves_html}). Updating the shared base layer resolves them across all dependents.</li>
            <li><strong>1 week:</strong> Address namespaces with most workloads: {top_ns_html}.</li>
            <li><strong>Ongoing:</strong> Enable Defender for Cloud registry scan on push. Block images with CVSS &ge; 9 via admission webhook before deploying to production.</li>
            <li><strong>Validation:</strong> After each rebuild, re-run <code>defender.sh</code> and <code>generate_report.py</code> to confirm CVEs are resolved.</li>
          </ol>
        </div>
      </div>
    </div>'''

    css = """
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:#F1F5F9;color:#1E293B;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
    code{background:#E2E8F0;color:#1E293B;padding:1px 5px;border-radius:4px;font-size:.88em;font-family:'Courier New',monospace}
    .mono{font-family:'Courier New',monospace;font-size:.85em}
    .topbar{background:#fff;border-bottom:1px solid #E2E8F0;padding:0 40px;height:58px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:200;box-shadow:0 1px 3px rgba(0,0,0,.06)}
    .brand{display:flex;align-items:center;gap:10px}
    .brand-dot{width:9px;height:9px;border-radius:50%;background:#059669;box-shadow:0 0 0 3px rgba(5,150,105,.18)}
    .brand-t{font-weight:700;font-size:.92em;color:#0F172A}
    .brand-s{color:#94A3B8;font-weight:400;font-size:.85em;margin-left:4px}
    .topbar-date{font-size:.78em;color:#94A3B8}
    .hero{background:linear-gradient(135deg,#0C3B2E 0%,#0A5C3C 55%,#059669 100%);padding:48px 40px 44px;color:#fff}
    .hero h1{font-size:1.6em;font-weight:300;letter-spacing:.3px}
    .hero h1 strong{font-weight:700}
    .hero p{opacity:.55;font-size:.83em;margin-top:8px;letter-spacing:.2px}
    .health-wrap{margin-top:32px;max-width:520px}
    .health-meta{display:flex;align-items:baseline;gap:12px;margin-bottom:10px}
    .health-lbl{font-size:.72em;text-transform:uppercase;letter-spacing:.9px;color:rgba(255,255,255,.5);font-weight:600}
    .health-score{font-size:2em;font-weight:800;line-height:1}
    .health-total{font-size:.45em;color:rgba(255,255,255,.4);font-weight:400;margin-left:2px}
    .health-tag{font-size:.68em;font-weight:700;text-transform:uppercase;letter-spacing:.5px;border-radius:20px;padding:3px 12px}
    .health-track{position:relative;height:10px;border-radius:99px;overflow:visible;margin-bottom:12px}
    .health-gradient-bar{position:absolute;inset:0;border-radius:99px;background:linear-gradient(to right,#DC2626 0%,#F97316 35%,#EAB308 60%,#22C55E 100%);opacity:.85}
    .health-marker{position:absolute;top:50%;transform:translateY(-50%);width:12px;height:12px;border-radius:50%;background:#fff;border:2px solid rgba(255,255,255,.9);box-shadow:0 0 0 3px rgba(0,0,0,.25);z-index:2}
    .health-fill{height:100%;border-radius:99px;transition:width .6s ease}
    .health-insight{font-size:.78em;color:rgba(255,255,255,.55);line-height:1.5;margin-top:0;font-style:italic}
    .drivers-section{background:#FAFBFC;border:1px solid #EEF2F7;border-radius:12px;padding:16px 20px;margin-bottom:22px;box-shadow:none}
    .drivers-header{display:flex;align-items:center;gap:7px;margin-bottom:13px}
    .drivers-title{font-size:.68em;font-weight:600;text-transform:uppercase;letter-spacing:.7px;color:#94A3B8}
    .drivers-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
    .driver-card{background:#fff;border:1px solid #F1F5F9;border-radius:9px;padding:12px 15px}
    .driver-card-name{font-size:.65em;text-transform:uppercase;letter-spacing:.5px;color:#CBD5E1;font-weight:600;margin-bottom:4px}
    .driver-card-val{font-size:.92em;font-weight:700;color:#475569;line-height:1.3}
    .container{max-width:1080px;margin:0 auto;padding:28px 20px 60px}
    .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:13px;margin-bottom:26px}
    @media(max-width:1000px){.kpis{grid-template-columns:repeat(3,1fr)}}
    @media(max-width:600px){.kpis{grid-template-columns:repeat(2,1fr)}}
    .kpi{background:#fff;border-radius:12px;padding:18px 14px;text-align:center;border:1px solid #E2E8F0;box-shadow:0 1px 4px rgba(0,0,0,.05);transition:box-shadow .18s}
    .kpi:hover{box-shadow:0 4px 14px rgba(0,0,0,.09)}
    .kpi svg{opacity:.4;margin-bottom:8px}
    .kpi-n{font-size:2em;font-weight:800;color:#0F172A;line-height:1}
    .kpi-n.red{color:#DC2626}
    .kpi-l{font-size:.68em;text-transform:uppercase;letter-spacing:.7px;color:#94A3B8;margin-top:5px;font-weight:600}
    .crit-alert{background:#FEF2F2;border:1px solid #FECACA;border-left:4px solid #DC2626;border-radius:10px;padding:14px 18px;margin-bottom:26px}
    .crit-hdr{display:flex;align-items:center;gap:8px;font-weight:700;font-size:.86em;color:#991B1B;margin-bottom:10px}
    .al-grid{display:flex;flex-wrap:wrap;gap:8px}
    .al-item{background:#fff;border:1px solid #FECACA;border-radius:8px;padding:7px 12px;display:flex;align-items:center;gap:7px;font-size:.82em}
    .al-ns{color:#94A3B8;font-weight:500}
    .al-sep{color:#FECACA}
    .al-name{color:#1E293B;font-weight:700}
    .stitle{font-size:.67em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#94A3B8;margin-bottom:11px;display:flex;align-items:center;gap:8px}
    .stitle::after{content:'';flex:1;height:1px;background:#E2E8F0}
    .tcves{background:#fff;border:1px solid #E2E8F0;border-radius:12px;overflow:hidden;margin-bottom:26px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
    .tcves table{width:100%;border-collapse:collapse}
    .tcves thead th{padding:10px 14px;text-align:left;font-size:.67em;text-transform:uppercase;letter-spacing:.7px;color:#94A3B8;font-weight:600;background:#F8FAFC;border-bottom:1px solid #E2E8F0}
    .tcves tbody tr{border-bottom:1px solid #F1F5F9;transition:background .12s}
    .tcves tbody tr:last-child{border:none}
    .tcves tbody tr:hover{background:#F8FAFC}
    .tcves td{padding:9px 14px;vertical-align:middle}
    .rank{color:#CBD5E1;font-weight:700;font-size:.8em;width:32px}
    .bar-cell{width:220px}
    .barw{display:flex;align-items:center;gap:8px}
    .barf{height:5px;background:#A7F3D0;border-radius:3px;min-width:3px}
    .barl{font-size:.77em;color:#64748B;font-weight:600;white-space:nowrap}
    .badge{display:inline-block;border-radius:20px;padding:2px 10px;font-size:.78em;font-weight:700;letter-spacing:.2px}
    .s-max{background:#FEE2E2;color:#991B1B}
    .s-crit{background:#FFEDD5;color:#9A3412}
    .s-high{background:#FEF9C3;color:#854D0E}
    .s-med{background:#DCFCE7;color:#166534}
    .wb{border-radius:20px;padding:2px 8px;font-size:.71em;font-weight:600}
    .wb-dep{background:#DBEAFE;color:#1D4ED8}
    .wb-dconf{background:#EDE9FE;color:#6D28D9}
    .wb-job{background:#FEF3C7;color:#92400E}
    .wb-ss{background:#DCFCE7;color:#15803D}
    .wb-pod{background:#FCE7F3;color:#9D174D}
    .wb-other{background:#F1F5F9;color:#475569}
    .pill{background:#F1F5F9;color:#64748B;border-radius:20px;padding:2px 8px;font-size:.71em;font-weight:600}
    .pill-y{background:#FEF9C3;color:#854D0E}
    .pill-red{background:#FEE2E2;color:#991B1B}
    .copy-btn{background:none;border:1px solid #E2E8F0;border-radius:4px;padding:1px 6px;margin-left:6px;cursor:pointer;color:#64748B;font-size:.85em;line-height:1;transition:all .12s}
    .copy-btn:hover{background:#F1F5F9;color:#0F172A;border-color:#CBD5E1}
    .copy-btn.ok{background:#DCFCE7;color:#166534;border-color:#86EFAC}
    .filters{position:sticky;top:58px;z-index:100;background:#fff;border:1px solid #E2E8F0;border-radius:10px;padding:10px 14px;margin-bottom:22px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;box-shadow:0 1px 4px rgba(0,0,0,.05)}
    .filters label{font-size:.75em;color:#64748B;font-weight:600;display:flex;align-items:center;gap:6px;text-transform:uppercase;letter-spacing:.4px}
    .filters select,.filters input{font-family:inherit;font-size:.88em;color:#0F172A;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:5px 8px;font-weight:400}
    .filters select:focus,.filters input:focus{outline:2px solid #0EA5E9;outline-offset:-1px;background:#fff}
    .filters input[type="text"]{flex:1;min-width:200px}
    .f-clear{background:#F1F5F9;border:1px solid #E2E8F0;border-radius:6px;padding:5px 12px;font-size:.82em;color:#475569;cursor:pointer;font-weight:600}
    .f-clear:hover{background:#E2E8F0}
    .f-count{font-size:.75em;color:#94A3B8;margin-left:auto;font-weight:600}
    .runs-in{font-size:.82em;color:#475569;margin-bottom:10px;padding:8px 10px;background:#F8FAFC;border-radius:6px;line-height:1.8}
    .runs-in strong{color:#0F172A;font-size:.9em;margin-right:6px}
    .run-chip{display:inline-flex;align-items:center;gap:4px;background:#fff;border:1px solid #E2E8F0;border-radius:6px;padding:2px 8px;margin:2px 4px 2px 0;font-size:.85em}
    .ns-tag{color:#94A3B8;font-size:.9em}
    .wl-cpill{background:#FFEDD5;color:#9A3412;border-radius:20px;padding:2px 8px;font-size:.71em;font-weight:600}
    .ns-card{background:#fff;border:1px solid #E2E8F0;border-radius:12px;margin-bottom:9px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.04)}
    .ns-btn{width:100%;background:none;border:none;cursor:pointer;padding:13px 16px;display:flex;align-items:center;justify-content:space-between;transition:background .14s}
    .ns-btn:hover{background:#F8FAFC}
    .ns-left{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
    .ns-right{display:flex;align-items:center;gap:8px}
    .ns-name{font-weight:700;font-size:.92em;color:#0F172A}
    .chev{transition:transform .2s;display:flex}
    .ns-body{display:none;padding:4px 16px 14px;border-top:1px solid #F1F5F9}
    .wl-card{background:#FAFAFA;border:1px solid #F1F5F9;border-radius:9px;padding:13px 15px;margin-top:11px}
    .wl-hdr{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:7px;margin-bottom:7px}
    .wl-left{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
    .wl-name{font-weight:700;font-size:.9em;color:#0F172A}
    .wl-img{display:flex;align-items:center;gap:5px;font-size:.77em;color:#94A3B8;margin-bottom:9px;flex-wrap:wrap}
    .wl-img .mono{color:#64748B}
    .digest-t{color:#94A3B8;font-size:.85em}
    .cve-tbl{width:100%;border-collapse:collapse;font-size:.82em}
    .cve-tbl thead tr{background:#F8FAFC}
    .cve-tbl th{padding:5px 9px;text-align:left;font-size:.68em;text-transform:uppercase;letter-spacing:.5px;color:#94A3B8;font-weight:600;border-bottom:1px solid #E2E8F0}
    .cve-tbl td{padding:6px 9px;border-bottom:1px solid #F1F5F9;vertical-align:middle}
    .cve-tbl tr:last-child td{border:none}
    .analysis{background:#fff;border:1px solid #E2E8F0;border-radius:14px;padding:26px;margin-top:36px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
    .a-hdr{display:flex;align-items:flex-start;gap:14px;padding-bottom:18px;border-bottom:1px solid #F1F5F9;margin-bottom:20px}
    .a-hdr h2{font-size:1.02em;font-weight:700;color:#0F172A}
    .a-hdr p{font-size:.79em;color:#94A3B8;margin-top:3px}
    .a-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    @media(max-width:720px){.a-grid{grid-template-columns:1fr}}
    .a-card{background:#F8FAFC;border:1px solid #E2E8F0;border-radius:10px;padding:16px}
    .a-red{background:#FEF2F2;border-color:#FECACA}
    .a-green{background:#F0FDF4;border-color:#BBF7D0}
    .a-title{display:flex;align-items:center;gap:7px;font-weight:700;font-size:.84em;color:#1E293B;margin-bottom:11px}
    .a-list{padding-left:16px;font-size:.82em;color:#475569;line-height:1.75}
    .a-list li{margin-bottom:7px}
    .nb-link{display:flex;align-items:center;gap:8px;text-decoration:none;color:inherit}
    .nb-link:hover .nb-name{color:#00693C}
    .nb-name{font-weight:800;font-size:.95em;color:#0F172A;letter-spacing:-.3px}
    .brand-sep{width:1px;height:22px;background:#E2E8F0;margin:0 6px}
    .footer{text-align:center;color:#CBD5E1;font-size:.72em;margin-top:36px;padding-bottom:16px}
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Container Vulnerability Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet"/>
<style>{css}</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <a href="https://www.novobanco.pt/particulares" target="_blank" rel="noopener" class="nb-link">
      <svg width="28" height="28" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="40" height="40" rx="6" fill="#00693C"/>
        <text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" fill="white" font-size="13" font-family="Inter,Segoe UI,sans-serif" font-weight="800">nb</text>
      </svg>
      <span class="nb-name">novobanco</span>
    </a>
    <div class="brand-sep"></div>
    <div class="brand-dot"></div>
    <span class="brand-t">Security Report <span class="brand-s">Defender for Cloud</span></span>
  </div>
  <span class="topbar-date">{now}</span>
</div>
<div class="hero">
  <h1><strong>Container Vulnerability</strong> Report</h1>
  <p>Microsoft Defender for Cloud &nbsp;&middot;&nbsp; Cluster Cross-Reference &nbsp;&middot;&nbsp; CVSS &ge; 9.0</p>
  <div class="health-wrap">
    <div class="health-meta">
      <span class="health-lbl">Cluster Health</span>
      <span class="health-score" style="color:{health_color}">{health_score}<span class="health-total">/100</span></span>
      <span class="health-tag" style="background:{health_color}22;color:{health_color};border:1px solid {health_color}44">{health_label}</span>
    </div>
    <div class="health-track">
      <div class="health-gradient-bar"></div>
      <div class="health-marker" style="left:calc({health_score}% - 6px)"></div>
    </div>
    <p class="health-insight">{health_insight}</p>
  </div>
</div>
<div class="container">
  <div class="kpis" style="margin-top:26px">
    <div class="kpi">{ic("namespace",20,"#94A3B8")}<div class="kpi-n">{total_ns}</div><div class="kpi-l">Namespaces</div></div>
    <div class="kpi">{ic("workload",20,"#94A3B8")}<div class="kpi-n">{total_w}</div><div class="kpi-l">Workloads</div></div>
    <div class="kpi">{ic("cve",20,"#94A3B8")}<div class="kpi-n">{unique_cves}</div><div class="kpi-l">Unique CVEs</div></div>
    <div class="kpi">{ic("entries",20,"#94A3B8")}<div class="kpi-n">{total_e}</div><div class="kpi-l">CVE Entries</div></div>
    <div class="kpi">{ic("critical",20,"#94A3B8")}<div class="kpi-n red">{s10_count}</div><div class="kpi-l">Score 10.0</div></div>
    <div class="kpi" title="CVE entries with verified exploit, published PoC, or known exploit kit">{ic("zap",20,"#94A3B8")}<div class="kpi-n {"red" if weap_count > 0 else ""}">{weap_count}</div><div class="kpi-l">Weaponized</div></div>
  </div>
  <div class="drivers-section">
    <div class="drivers-header">
      {ic("alert",14,"#94A3B8")}
      <span class="drivers-title">Drivers of Risk</span>
    </div>
    <div class="drivers-grid">
      {"".join(
          f'<div class="driver-card">'
          f'<div class="driver-card-name">{name}</div>'
          f'<div class="driver-card-val">{detail}</div>'
          f'</div>'
          for name, _pct, detail in risk_drivers
      )}
    </div>
  </div>
  {alert_html}
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
        <option value="1">Any exploit</option>
      </select>
    </label>
    <input type="text" id="fSearch" placeholder="Filter by namespace / repo / workload…" oninput="applyFilters()"/>
    <button class="f-clear" onclick="clearFilters()">Clear</button>
    <span class="f-count" id="fCount"></span>
  </div>
  <div class="stitle">Vulnerable Images &mdash; sorted by max CVSS</div>
  {image_cards}
  <div class="stitle">Most Widespread CVEs</div>
  {cve_accordion}
  <div class="stitle">Namespace Detail &mdash; sorted by CVE count</div>
  {ns_html}
  {analysis}
  <div class="footer">Confidential &nbsp;&middot;&nbsp; Internal Use Only &nbsp;&middot;&nbsp; {now}</div>
</div>
<script>
function toggle(b){{var d=b.nextElementSibling;var o=d.style.display==='block';d.style.display=o?'none':'block';var c=b.querySelector('.chev');if(c)c.style.transform=o?'':'rotate(180deg)';}}
function cpy(btn){{event.stopPropagation();var t=btn.dataset.copy||'';if(navigator.clipboard){{navigator.clipboard.writeText(t).then(function(){{var o=btn.textContent;btn.textContent='✓';btn.classList.add('ok');setTimeout(function(){{btn.textContent=o;btn.classList.remove('ok');}},900);}});}}}}
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
    if(expl==='1'&&row.dataset.expl!=='1')ok=false;
    row.style.display=ok?'':'none';
  }});
  document.querySelectorAll('.ns-card').forEach(function(card){{
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
