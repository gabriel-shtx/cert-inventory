#!/usr/bin/env python3
"""
cert-inventory.py — Inventário de certificados emitidos via Certificate Transparency (crt.sh),
                    agrupado pela Autoridade Certificadora (CA) emissora.

Uso:
    python3 cert-inventory.py jacto.com.br jacto.com.ar
    python3 cert-inventory.py -f dominios.txt
    python3 cert-inventory.py -f dominios.txt --ativos --csv certs.csv
    python3 cert-inventory.py -f dominios.txt --html painel.html

Fontes:
    - crt.sh (Sectigo) via API JSON
"""

import argparse
import csv
import html as html_mod
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta

CRTSH = "https://crt.sh/?q={}&output=json"
UA = "cert-inventory/1.0 (+asset-inventory)"
EXPIRING_DAYS = 30  # janela para "expira em breve"


def fetch_crtsh(domain, retries=3, timeout=60):
    """Consulta o crt.sh para %.<domain> e retorna a lista de registros."""
    q = urllib.parse.quote(f"%.{domain}")
    url = CRTSH.format(q)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", "replace").strip()
            if not raw:
                return []
            return json.loads(raw)
        except json.JSONDecodeError:
            try:
                return [json.loads(l) for l in raw.splitlines() if l.strip()]
            except Exception:
                pass
        except Exception as e:
            sys.stderr.write(f"[!] {domain}: tentativa {attempt}/{retries} falhou ({e})\n")
            time.sleep(2 * attempt)
    return []


def parse_issuer(issuer_name):
    """Extrai um rótulo legível da CA a partir do issuer_name (formato RDN)."""
    if not issuer_name:
        return "Desconhecida"
    o = re.search(r"O=([^,]+)", issuer_name)
    cn = re.search(r"CN=([^,]+)", issuer_name)
    org = o.group(1).strip('" ') if o else None
    common = cn.group(1).strip('" ') if cn else None
    if org and common:
        return f"{org} — {common}"
    return org or common or issuer_name.strip()


def ca_org(issuer_name):
    """Organização raiz da CA (para agrupar famílias: Let's Encrypt, DigiCert...)."""
    o = re.search(r"O=([^,]+)", issuer_name or "")
    if o:
        return o.group(1).strip('" ')
    return parse_issuer(issuer_name)


def _dt(s):
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def status_of(not_after):
    """valido | expira | expirado | ? — com base no not_after."""
    dt = _dt(not_after)
    if dt is None:
        return "?"
    now = datetime.now(timezone.utc)
    if dt < now:
        return "expirado"
    if dt < now + timedelta(days=EXPIRING_DAYS):
        return "expira"
    return "valido"


def collect(domains, sleep=1.0, ativos=False):
    """Consulta todos os domínios e devolve linhas normalizadas e deduplicadas."""
    rows, seen = [], set()
    for i, d in enumerate(domains):
        sys.stderr.write(f"[*] Consultando {d} ({i+1}/{len(domains)})...\n")
        for rec in fetch_crtsh(d):
            cid = rec.get("id")
            if cid in seen:
                continue
            seen.add(cid)
            st = status_of(rec.get("not_after", ""))
            if ativos and st == "expirado":
                continue
            rows.append({
                "ca": parse_issuer(rec.get("issuer_name", "")),
                "ca_org": ca_org(rec.get("issuer_name", "")),
                "common_name": rec.get("common_name", "") or "",
                "name_value": str(rec.get("name_value", "")).replace("\n", " ").strip(),
                "not_before": rec.get("not_before", ""),
                "not_after": rec.get("not_after", ""),
                "status": st,
                "serial": rec.get("serial_number", ""),
                "crtsh_id": cid,
                "dominio_consultado": d,
            })
        time.sleep(sleep)
    return rows


# ------------------------------- Relatório texto ------------------------------
def report_text(rows, ativos=False):
    ca_stats = defaultdict(lambda: {"count": 0, "domains": set(), "names": set()})
    for r in rows:
        s = ca_stats[r["ca"]]
        s["count"] += 1
        s["domains"].add(r["dominio_consultado"])
        s["names"].add(r["common_name"].lstrip("*."))
    total = len(rows)
    print("\n" + "=" * 70)
    print(f"  INVENTÁRIO DE CERTIFICADOS POR CA — {total} certificados")
    if ativos:
        print("  (apenas certificados válidos / não expirados)")
    print("=" * 70)
    for ca, v in sorted(ca_stats.items(), key=lambda kv: kv[1]["count"], reverse=True):
        pct = (v["count"] / total * 100) if total else 0
        print(f"\n▸ {ca}")
        print(f"    Certificados : {v['count']}  ({pct:.1f}%)")
        print(f"    Domínios     : {', '.join(sorted(v['domains']))}")
        print(f"    Hosts únicos : {len(v['names'])}")
    print("\n" + "-" * 70)
    print(f"  Total de CAs distintas: {len(ca_stats)}")
    print("-" * 70)


# --------------------------------- CSV ----------------------------------------
def write_csv(rows, path):
    if not rows:
        return
    cols = ["ca", "common_name", "name_value", "not_before", "not_after",
            "status", "serial", "crtsh_id", "dominio_consultado"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    sys.stderr.write(f"[+] CSV exportado: {path} ({len(rows)} linhas)\n")


# --------------------------------- HTML ---------------------------------------
CA_PALETTE = ["#34D3A6", "#8B93F8", "#56B6E6", "#F5B542", "#F16C6C",
              "#7FD98C", "#E67CC5", "#C0A3F0", "#6FD0C4", "#9AA6BE"]


def build_html_payload(rows, domains):
    total = len(rows)
    # famílias de CA (por organização) rankeadas
    fam = Counter(r["ca_org"] for r in rows)
    fam_ranked = fam.most_common()
    color_map = {}
    for i, (name, _) in enumerate(fam_ranked):
        color_map[name] = CA_PALETTE[i] if i < len(CA_PALETTE) - 1 else CA_PALETTE[-1]

    status_counts = Counter(r["status"] for r in rows)

    # horizonte de renovação: baldes por mês (próximos 12) + vencidos
    now = datetime.now(timezone.utc)
    buckets = {}  # 'YYYY-MM' -> {valido,expira}
    overdue = 0
    for r in rows:
        dt = _dt(r["not_after"])
        if dt is None:
            continue
        if dt < now:
            overdue += 1
            continue
        if dt > now + timedelta(days=366):
            continue
        key = f"{dt.year:04d}-{dt.month:02d}"
        b = buckets.setdefault(key, {"expira": 0, "valido": 0})
        b["expira" if r["status"] == "expira" else "valido"] += 1
    months = []
    cur = now.replace(day=1)
    for _ in range(13):
        key = f"{cur.year:04d}-{cur.month:02d}"
        b = buckets.get(key, {"expira": 0, "valido": 0})
        months.append({"key": key, "label": cur.strftime("%b/%y"),
                       "expira": b["expira"], "valido": b["valido"]})
        cur = (cur.replace(day=28) + timedelta(days=7)).replace(day=1)

    # próximas expirações (as 15 mais próximas, não vencidas)
    upcoming = sorted(
        [r for r in rows if r["status"] in ("expira", "valido") and _dt(r["not_after"])],
        key=lambda r: _dt(r["not_after"]))[:15]

    ca_table = [{"name": n, "count": c, "pct": round(c / total * 100, 1) if total else 0,
                 "color": color_map[n]} for n, c in fam_ranked]

    def slim(r):
        return {"host": r["common_name"] or r["name_value"], "ca": r["ca"],
                "ca_org": r["ca_org"], "nb": r["not_before"][:10],
                "na": r["not_after"][:10], "status": r["status"],
                "dom": r["dominio_consultado"],
                "color": color_map.get(r["ca_org"], "#9AA6BE")}

    return {
        "generated": now.strftime("%Y-%m-%d %H:%M UTC"),
        "domains": domains,
        "total": total,
        "ca_count": len(fam_ranked),
        "status": {"valido": status_counts.get("valido", 0),
                   "expira": status_counts.get("expira", 0),
                   "expirado": status_counts.get("expirado", 0),
                   "desconhecido": status_counts.get("?", 0)},
        "ca_table": ca_table,
        "months": months,
        "overdue": overdue,
        "upcoming": [slim(r) for r in upcoming],
        "rows": [slim(r) for r in rows],
        "expiring_days": EXPIRING_DAYS,
    }


def write_html(rows, domains, path):
    payload = build_html_payload(rows, domains)
    data_json = json.dumps(payload, ensure_ascii=False)
    doc = HTML_TEMPLATE.replace("/*__DATA__*/null", data_json)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    sys.stderr.write(f"[+] HTML exportado: {path} ({len(rows)} certificados)\n")


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Inventário de Certificados · CT Ledger</title>
<style>
  :root{
    --bg:#0C1018; --surface:#141A24; --surface2:#1B2330; --line:#263041;
    --text:#E7ECF3; --muted:#8792A6; --faint:#5A6479;
    --valid:#34D3A6; --warn:#F5B542; --danger:#F16C6C;
    --mono: ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans: system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{
    background:
      radial-gradient(1200px 600px at 85% -10%, rgba(52,211,166,.08), transparent 60%),
      var(--bg);
    color:var(--text); font-family:var(--sans);
    -webkit-font-smoothing:antialiased; line-height:1.45;
  }
  .wrap{max-width:1160px; margin:0 auto; padding:40px 28px 80px}
  .eyebrow{font-family:var(--mono); font-size:11px; letter-spacing:.22em;
    text-transform:uppercase; color:var(--valid)}
  header .eyebrow{color:var(--muted)}
  h1{font-size:30px; line-height:1.1; margin:8px 0 6px; font-weight:650; letter-spacing:-.01em}
  h1 b{color:var(--valid); font-weight:650}
  .sub{color:var(--muted); font-family:var(--mono); font-size:12.5px; letter-spacing:.02em}
  .sub .dom{color:var(--text)}
  .rule{height:1px; background:linear-gradient(90deg,var(--line),transparent);
    margin:26px 0 30px}

  /* KPIs */
  .kpis{display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:34px}
  .kpi{background:var(--surface); border:1px solid var(--line); border-radius:12px;
    padding:18px 18px 16px; position:relative; overflow:hidden}
  .kpi .n{font-family:var(--mono); font-size:34px; font-weight:600;
    font-variant-numeric:tabular-nums; letter-spacing:-.02em; line-height:1}
  .kpi .l{font-family:var(--mono); font-size:10.5px; letter-spacing:.16em;
    text-transform:uppercase; color:var(--muted); margin-top:9px}
  .kpi .tick{position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--valid)}
  .kpi.warn .n{color:var(--warn)} .kpi.warn .tick{background:var(--warn)}
  .kpi.danger .n{color:var(--danger)} .kpi.danger .tick{background:var(--danger)}
  .kpi.valid .n{color:var(--valid)}

  .grid{display:grid; grid-template-columns:1.35fr 1fr; gap:20px; margin-bottom:24px}
  .card{background:var(--surface); border:1px solid var(--line); border-radius:14px; padding:22px 22px 20px}
  .card h2{font-size:13px; font-family:var(--mono); letter-spacing:.06em; text-transform:uppercase;
    color:var(--text); margin:0 0 4px; font-weight:600}
  .card p.hint{color:var(--muted); font-size:12.5px; margin:0 0 18px}

  /* CA bars */
  .bar-row{display:grid; grid-template-columns:170px 1fr 54px; align-items:center;
    gap:12px; margin:11px 0}
  .bar-row .name{font-size:13px; color:var(--text); white-space:nowrap; overflow:hidden;
    text-overflow:ellipsis; display:flex; align-items:center; gap:8px}
  .dot{width:9px; height:9px; border-radius:2px; flex:none}
  .track{height:20px; background:var(--surface2); border-radius:5px; overflow:hidden}
  .fill{height:100%; border-radius:5px; width:0; transition:width .9s cubic-bezier(.2,.8,.2,1)}
  .bar-row .v{font-family:var(--mono); font-size:12.5px; text-align:right;
    color:var(--muted); font-variant-numeric:tabular-nums}

  /* donut */
  .donut-wrap{display:flex; align-items:center; gap:24px}
  .donut{width:150px; height:150px; border-radius:50%; flex:none; position:relative}
  .donut::after{content:""; position:absolute; inset:26px; background:var(--surface);
    border-radius:50%}
  .donut .center{position:absolute; inset:0; display:flex; flex-direction:column;
    align-items:center; justify-content:center; z-index:2}
  .donut .center .big{font-family:var(--mono); font-size:26px; font-weight:600; line-height:1}
  .donut .center .cap{font-family:var(--mono); font-size:9px; letter-spacing:.14em;
    text-transform:uppercase; color:var(--muted); margin-top:3px}
  .legend{display:flex; flex-direction:column; gap:12px; font-size:13px}
  .legend .li{display:flex; align-items:center; gap:10px}
  .legend .sw{width:11px; height:11px; border-radius:3px; flex:none}
  .legend .lv{font-family:var(--mono); margin-left:auto; color:var(--muted);
    font-variant-numeric:tabular-nums}

  /* timeline / horizonte */
  .timeline{margin-top:6px}
  .tl-head{display:flex; justify-content:space-between; align-items:baseline; margin-bottom:14px}
  .tl-chart{display:grid; grid-template-columns:64px 1fr; gap:14px; align-items:end}
  .overdue-col{display:flex; flex-direction:column; align-items:center; justify-content:flex-end;
    height:180px; border-right:1px dashed var(--line); padding-right:12px}
  .overdue-col .bar{width:34px; background:linear-gradient(180deg,var(--danger),#B84545);
    border-radius:5px 5px 0 0; min-height:3px}
  .overdue-col .cap{font-family:var(--mono); font-size:9px; letter-spacing:.1em;
    text-transform:uppercase; color:var(--danger); margin-top:8px; text-align:center}
  .overdue-col .num{font-family:var(--mono); font-size:14px; color:var(--danger); margin-bottom:6px}
  .months{display:flex; gap:6px; height:180px; align-items:flex-end}
  .mcol{flex:1; display:flex; flex-direction:column; align-items:center; justify-content:flex-end;
    height:100%; position:relative}
  .mstack{width:100%; max-width:30px; display:flex; flex-direction:column-reverse; border-radius:5px 5px 0 0;
    overflow:hidden; min-height:2px}
  .seg{width:100%}
  .seg.valid{background:linear-gradient(180deg,#34D3A6,#249e7c)}
  .seg.warn{background:linear-gradient(180deg,#F5B542,#c78d2c)}
  .mcol .mlabel{font-family:var(--mono); font-size:9.5px; color:var(--muted); margin-top:9px;
    white-space:nowrap; transform:rotate(0deg)}
  .mcol .mtotal{font-family:var(--mono); font-size:10px; color:var(--faint); margin-bottom:5px; height:12px}
  .mcol.now .mlabel{color:var(--valid)}
  .mcol.now::before{content:"AGORA"; position:absolute; top:-4px; font-family:var(--mono);
    font-size:8px; letter-spacing:.12em; color:var(--valid)}

  /* upcoming list */
  .up{display:flex; flex-direction:column}
  .up .row{display:grid; grid-template-columns:1fr auto auto; gap:12px; align-items:center;
    padding:10px 0; border-top:1px solid var(--line)}
  .up .row:first-child{border-top:0}
  .up .host{font-size:13px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
  .up .host .ca{display:block; font-family:var(--mono); font-size:10.5px; color:var(--muted)}
  .up .when{font-family:var(--mono); font-size:12px; color:var(--muted); font-variant-numeric:tabular-nums}
  .badge{font-family:var(--mono); font-size:9.5px; letter-spacing:.08em; text-transform:uppercase;
    padding:3px 8px; border-radius:20px; white-space:nowrap}
  .badge.valid{background:rgba(52,211,166,.14); color:var(--valid)}
  .badge.expira{background:rgba(245,181,66,.15); color:var(--warn)}
  .badge.expirado{background:rgba(241,108,108,.15); color:var(--danger)}

  /* table */
  .tablecard{margin-top:24px}
  .tbar{display:flex; gap:12px; align-items:center; margin-bottom:16px; flex-wrap:wrap}
  .search{flex:1; min-width:220px; background:var(--surface2); border:1px solid var(--line);
    border-radius:9px; padding:10px 13px; color:var(--text); font-family:var(--mono);
    font-size:13px; outline:none}
  .search:focus{border-color:var(--valid)}
  .search::placeholder{color:var(--faint)}
  .chip{font-family:var(--mono); font-size:11px; letter-spacing:.04em; padding:8px 13px;
    border-radius:9px; border:1px solid var(--line); background:var(--surface2); color:var(--muted);
    cursor:pointer; user-select:none; text-transform:uppercase}
  .chip.on{color:var(--bg); border-color:transparent}
  .chip.on[data-f="valido"]{background:var(--valid)}
  .chip.on[data-f="expira"]{background:var(--warn)}
  .chip.on[data-f="expirado"]{background:var(--danger)}
  .chip.on[data-f="all"]{background:var(--text)}
  table{width:100%; border-collapse:collapse}
  thead th{font-family:var(--mono); font-size:10px; letter-spacing:.12em; text-transform:uppercase;
    color:var(--muted); text-align:left; padding:0 12px 12px; border-bottom:1px solid var(--line);
    cursor:pointer; user-select:none; white-space:nowrap}
  thead th:hover{color:var(--text)}
  tbody td{padding:11px 12px; border-bottom:1px solid rgba(38,48,65,.55); font-size:13px; vertical-align:middle}
  tbody tr:hover{background:rgba(27,35,48,.5)}
  td.host{font-family:var(--mono); font-size:12.5px; max-width:340px; overflow:hidden;
    text-overflow:ellipsis; white-space:nowrap}
  td.ca{color:var(--muted); font-size:12px}
  td.ca .dot{display:inline-block; margin-right:7px; vertical-align:middle}
  td.date{font-family:var(--mono); font-size:12px; color:var(--muted); font-variant-numeric:tabular-nums; white-space:nowrap}
  .st{display:inline-flex; align-items:center; gap:6px; font-family:var(--mono); font-size:11px}
  .st::before{content:""; width:7px; height:7px; border-radius:50%}
  .st.valido{color:var(--valid)} .st.valido::before{background:var(--valid)}
  .st.expira{color:var(--warn)} .st.expira::before{background:var(--warn)}
  .st.expirado{color:var(--danger)} .st.expirado::before{background:var(--danger)}
  .count{font-family:var(--mono); font-size:11.5px; color:var(--faint); margin-top:12px}
  footer{margin-top:40px; color:var(--faint); font-family:var(--mono); font-size:11px;
    letter-spacing:.03em; display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px}

  @media (max-width:820px){
    .kpis{grid-template-columns:repeat(2,1fr)}
    .grid{grid-template-columns:1fr}
    .bar-row{grid-template-columns:120px 1fr 44px}
  }
  @media (prefers-reduced-motion:reduce){.fill{transition:none}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="eyebrow">Certificate Transparency · crt.sh</div>
    <h1>Inventário de <b>Certificados</b> por Autoridade</h1>
    <div class="sub" id="sub"></div>
  </header>
  <div class="rule"></div>

  <div class="kpis" id="kpis"></div>

  <div class="grid">
    <div class="card">
      <h2>Distribuição por CA</h2>
      <p class="hint">Certificados emitidos por organização certificadora (famílias agrupadas).</p>
      <div id="bars"></div>
    </div>
    <div class="card">
      <h2>Saúde da carteira</h2>
      <p class="hint">Status de validade no momento da coleta.</p>
      <div class="donut-wrap">
        <div class="donut" id="donut"><div class="center"><div class="big" id="dcenter"></div><div class="cap">certificados</div></div></div>
        <div class="legend" id="legend"></div>
      </div>
    </div>
  </div>

  <div class="card timeline">
    <div class="tl-head">
      <div><h2>Horizonte de renovação</h2>
      <p class="hint" style="margin-bottom:0">Certificados que expiram por mês (próximos 12) e o passivo já vencido.</p></div>
    </div>
    <div class="tl-chart">
      <div class="overdue-col" id="overdue"></div>
      <div class="months" id="months"></div>
    </div>
  </div>

  <div class="grid" style="margin-top:24px">
    <div class="card">
      <h2>Próximas expirações</h2>
      <p class="hint">As 15 datas de expiração mais próximas — priorize a renovação daqui.</p>
      <div class="up" id="upcoming"></div>
    </div>
    <div class="card">
      <h2>Como ler</h2>
      <p class="hint" style="margin-bottom:16px">Duas linguagens de cor:</p>
      <div class="legend" style="gap:14px">
        <div class="li"><span class="sw" style="background:var(--valid)"></span>Válido — fora da janela de risco</div>
        <div class="li"><span class="sw" style="background:var(--warn)"></span>Expira em breve — renovar já</div>
        <div class="li"><span class="sw" style="background:var(--danger)"></span>Vencido — passivo / possível host morto</div>
      </div>
      <p class="hint" style="margin:18px 0 0; line-height:1.6">
        CT log mostra o que foi <b style="color:var(--text)">emitido</b>, não o que está instalado.
        Uma CA fora do padrão corporativo pode indicar shadow IT ou emissão indevida — investigue os hosts vivos para confirmar.
      </p>
    </div>
  </div>

  <div class="card tablecard">
    <div class="tbar">
      <input class="search" id="q" placeholder="filtrar por host, CA ou domínio…" autocomplete="off">
      <span class="chip on" data-f="all">todos</span>
      <span class="chip" data-f="valido">válidos</span>
      <span class="chip" data-f="expira">expira &lt;30d</span>
      <span class="chip" data-f="expirado">vencidos</span>
    </div>
    <table>
      <thead><tr>
        <th data-s="host">Host</th>
        <th data-s="ca">CA emissora</th>
        <th data-s="nb">Emitido</th>
        <th data-s="na">Expira</th>
        <th data-s="status">Status</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
    <div class="count" id="count"></div>
  </div>

  <footer>
    <span id="footL"></span>
    <span>cert-inventory · fonte crt.sh (Certificate Transparency)</span>
  </footer>
</div>

<script>
const DATA = /*__DATA__*/null;
const ST = {valido:"Válido", expira:"Expira <30d", expirado:"Vencido", "?":"?"};
const el = (t,c,h)=>{const e=document.createElement(t); if(c)e.className=c; if(h!=null)e.innerHTML=h; return e;};

// sub
document.getElementById('sub').innerHTML =
  'Alvos: <span class="dom">'+DATA.domains.map(d=>d).join(' · ')+'</span> &nbsp;·&nbsp; '+DATA.generated;
document.getElementById('footL').textContent = 'gerado em '+DATA.generated;

// KPIs
const kpis=[
  {n:DATA.total, l:"certificados", cls:""},
  {n:DATA.ca_count, l:"autoridades", cls:"valid"},
  {n:DATA.status.expira, l:"expiram <"+DATA.expiring_days+"d", cls:"warn"},
  {n:DATA.status.expirado, l:"vencidos", cls:"danger"},
];
const kw=document.getElementById('kpis');
kpis.forEach(k=>{const c=el('div','kpi '+k.cls);
  c.appendChild(el('div','tick'));
  c.appendChild(el('div','n', k.n.toLocaleString('pt-BR')));
  c.appendChild(el('div','l', k.l)); kw.appendChild(c);});

// CA bars
const bw=document.getElementById('bars');
const maxCA = Math.max(1, ...DATA.ca_table.map(c=>c.count));
DATA.ca_table.slice(0,10).forEach((c,i)=>{
  const row=el('div','bar-row');
  const name=el('div','name');
  name.appendChild(el('span','dot','')); name.lastChild.style.background=c.color;
  name.appendChild(document.createTextNode(c.name));
  const track=el('div','track'); const fill=el('div','fill');
  fill.style.background=c.color;
  const v=el('div','v', c.count+' · '+c.pct+'%');
  row.append(name,track,v); bw.appendChild(row);
  requestAnimationFrame(()=>{ setTimeout(()=>{ fill.style.width=(c.count/maxCA*100)+'%'; }, 60*i); });
  track.appendChild(fill);
});

// donut (conic)
const s=DATA.status, tot=Math.max(1, s.valido+s.expira+s.expirado);
const segs=[["var(--valid)",s.valido],["var(--warn)",s.expira],["var(--danger)",s.expirado]];
let acc=0, stops=[];
segs.forEach(([col,val])=>{const a=acc/tot*360, b=(acc+val)/tot*360; stops.push(col+' '+a+'deg '+b+'deg'); acc+=val;});
document.getElementById('donut').style.background='conic-gradient('+stops.join(',')+')';
document.getElementById('dcenter').textContent=DATA.total.toLocaleString('pt-BR');
const lg=document.getElementById('legend');
[["Válidos","var(--valid)",s.valido],["Expira <30d","var(--warn)",s.expira],["Vencidos","var(--danger)",s.expirado]]
.forEach(([lab,col,val])=>{const li=el('div','li');
  const sw=el('span','sw',''); sw.style.background=col;
  li.appendChild(sw); li.appendChild(document.createTextNode(lab));
  const lv=el('span','lv', val.toLocaleString('pt-BR')); li.appendChild(lv); lg.appendChild(li);});

// timeline
const allMonthVals=DATA.months.map(m=>m.valido+m.expira).concat([DATA.overdue]);
const maxM=Math.max(1,...allMonthVals);
const H=180;
const ov=document.getElementById('overdue');
ov.appendChild(el('div','num', DATA.overdue));
const ob=el('div','bar',''); ob.style.height=(DATA.overdue/maxM*H)+'px'; ov.appendChild(ob);
ov.appendChild(el('div','cap','vencidos'));
const mw=document.getElementById('months');
const nowKey=DATA.months[0].key;
DATA.months.forEach((m,i)=>{
  const col=el('div','mcol'+(i===0?' now':''));
  const t=m.valido+m.expira;
  col.appendChild(el('div','mtotal', t>0? t: ''));
  const stack=el('div','mstack');
  const hv=(m.valido/maxM*H), he=(m.expira/maxM*H);
  const sv=el('div','seg valid',''); sv.style.height=hv+'px';
  const se=el('div','seg warn',''); se.style.height=he+'px';
  stack.append(sv,se);
  if(t===0){stack.style.minHeight='2px'; stack.style.background='var(--surface2)';}
  col.appendChild(stack);
  col.appendChild(el('div','mlabel', m.label));
  mw.appendChild(col);
});

// upcoming
const uw=document.getElementById('upcoming');
if(!DATA.upcoming.length) uw.appendChild(el('div','hint','Nenhuma expiração futura na coleta.'));
DATA.upcoming.forEach(r=>{
  const row=el('div','row');
  const h=el('div','host'); h.textContent=r.host;
  h.appendChild(el('span','ca', r.ca));
  row.appendChild(h);
  row.appendChild(el('div','when', r.na));
  row.appendChild(el('span','badge '+r.status, r.status==='valido'?'ok':(r.status==='expira'?'<30d':'venc')));
  uw.appendChild(row);
});

// table
let filter='all', q='', sortKey='na', sortDir=1;
const tb=document.getElementById('tbody'), cnt=document.getElementById('count');
function render(){
  let rows=DATA.rows.filter(r=>{
    if(filter!=='all' && r.status!==filter) return false;
    if(q){const s=(r.host+' '+r.ca+' '+r.dom).toLowerCase(); if(!s.includes(q)) return false;}
    return true;
  });
  rows.sort((a,b)=>{let x=(a[sortKey]||''),y=(b[sortKey]||''); return x<y?-sortDir:x>y?sortDir:0;});
  tb.innerHTML='';
  rows.slice(0,600).forEach(r=>{
    const tr=el('tr');
    const td1=el('td','host'); td1.textContent=r.host; td1.title=r.host;
    const td2=el('td','ca'); const d=el('span','dot',''); d.style.background=r.color;
    td2.appendChild(d); td2.appendChild(document.createTextNode(r.ca)); td2.title=r.ca;
    const td3=el('td','date', r.nb);
    const td4=el('td','date', r.na);
    const td5=el('td'); td5.innerHTML='<span class="st '+r.status+'">'+(ST[r.status]||r.status)+'</span>';
    tr.append(td1,td2,td3,td4,td5); tb.appendChild(tr);
  });
  cnt.textContent = rows.length.toLocaleString('pt-BR')+' de '+DATA.total.toLocaleString('pt-BR')+' certificados'+(rows.length>600?' (mostrando 600)':'');
}
document.getElementById('q').addEventListener('input', e=>{q=e.target.value.toLowerCase().trim(); render();});
document.querySelectorAll('.chip').forEach(c=>c.addEventListener('click',()=>{
  document.querySelectorAll('.chip').forEach(x=>x.classList.remove('on'));
  c.classList.add('on'); filter=c.dataset.f; render();
}));
document.querySelectorAll('thead th').forEach(th=>th.addEventListener('click',()=>{
  const k=th.dataset.s; if(k===sortKey) sortDir*=-1; else {sortKey=k; sortDir=1;} render();
}));
render();
</script>
</body>
</html>"""


def main():
    ap = argparse.ArgumentParser(description="Inventário de certificados por CA via crt.sh")
    ap.add_argument("domains", nargs="*", help="domínios (ex: jacto.com.br)")
    ap.add_argument("-f", "--file", help="arquivo com um domínio por linha")
    ap.add_argument("--ativos", action="store_true", help="somente certificados válidos (não expirados)")
    ap.add_argument("--csv", help="exporta os certificados para CSV")
    ap.add_argument("--html", help="gera painel HTML self-contained")
    ap.add_argument("--sleep", type=float, default=1.0, help="pausa entre domínios (rate limit)")
    args = ap.parse_args()

    domains = list(args.domains)
    if args.file:
        with open(args.file) as fh:
            domains += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    domains = sorted(set(domains))
    if not domains:
        ap.error("informe ao menos um domínio ou use -f")

    rows = collect(domains, sleep=args.sleep, ativos=args.ativos)
    report_text(rows, ativos=args.ativos)
    if args.csv:
        write_csv(rows, args.csv)
    if args.html:
        write_html(rows, domains, args.html)


if __name__ == "__main__":
    main()
