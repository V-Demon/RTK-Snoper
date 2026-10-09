#!/usr/bin/env python3
"""
RTK Request Studio (Édition Monofichier & Pédagogique)
========================================================
Client HTTP instrumenté (type "Repeater") pour rejouer, à partir d'une
bibliothèque de templates JSON externalisée, les sondes de vérification
associées aux scénarios RTK (SSRF, fuite de stack trace, CORS permissif,
traversée de chemin, listing de bucket public...).

- Les templates sont chargés depuis 'attack_templates.json'.
- L'envoi des requêtes utilise PycURL (libcurl) ; un mode "aperçu seul"
  reste disponible si PycURL n'est pas installé.
- Un périmètre d'engagement doit être déclaré avant tout envoi : les
  requêtes dont l'hôte cible ne correspond à aucune entrée du périmètre
  sont automatiquement ignorées (et journalisées comme telles).

⚠️  Usage strictement réservé aux engagements de sécurité autorisés,
    contre des cibles que vous possédez ou que vous êtes explicitement
    mandaté à tester. Cet outil n'exploite aucune vulnérabilité par
    lui-même : il envoie des requêtes HTTP et journalise les réponses,
    à charge pour l'opérateur d'interpréter les résultats.

Version : 1.0.0
"""

from __future__ import annotations

import json
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse
import tkinter as tk

try:
    import pycurl
    from io import BytesIO
    PYCURL_AVAILABLE = True
except ImportError:
    PYCURL_AVAILABLE = False


# ==============================================================================
# 1. CHARGEMENT DE LA BIBLIOTHÈQUE DE TEMPLATES
# ==============================================================================
def load_templates() -> list[dict]:
    json_path = Path(__file__).parent / "attack_templates.json"
    if not json_path.exists():
        raise FileNotFoundError(
            f"Le fichier 'attack_templates.json' est introuvable dans :\n"
            f"{json_path.parent}\nPlacez-le au même niveau que app.py."
        )
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("templates", [])
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Erreur de syntaxe JSON dans attack_templates.json "
            f"(ligne {e.lineno}, col {e.colno}) : {e.msg}"
        )


# ==============================================================================
# 2. THÈME / CONSTANTES UI
# ==============================================================================
BG_ROOT = "#0f1420"
BG_PANEL = "#161d2e"
BG_PANEL_ALT = "#1b2338"
BG_CARD = "#202a42"
BG_CARD_HOVER = "#263152"
BG_INPUT = "#111727"
FG_TEXT = "#e7ebf5"
FG_MUTED = "#8793b0"
FG_SUBTLE = "#5f6b8a"
ACCENT = "#5ad1c0"
ACCENT_DARK = "#2f8f82"
WARN = "#f0a35e"
CRIT = "#e1636e"
OK = "#79d17c"
BORDER = "#2a3450"

SEVERITY_COLOR = {
    "critical": CRIT, "high": "#e8905a", "medium": "#e0c158",
    "low": FG_MUTED, "info": FG_MUTED,
}


def severity_color(sev: str) -> str:
    return SEVERITY_COLOR.get((sev or "").lower().strip(), FG_MUTED)


# ==============================================================================
# 3. MOTEUR DE TEMPLATING & CONSTRUCTION DES REQUÊTES
# ==============================================================================
PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def render_text(text: str, params: dict) -> str:
    """Remplace {{cle}} par sa valeur dans params (simple substitution, pas d'eval)."""
    if not text:
        return text

    def _sub(m: re.Match) -> str:
        key = m.group(1)
        return str(params.get(key, m.group(0)))

    return PLACEHOLDER_RE.sub(_sub, text)


def sanitize_header_value(value: str) -> str:
    """Empêche l'injection d'en-têtes (CRLF) depuis un paramètre utilisateur."""
    return re.sub(r"[\r\n]", "", value or "")


@dataclass
class ResolvedRequest:
    index: int
    name: str
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str = ""
    # Rempli après exécution :
    status: int | None = None
    elapsed: float | None = None
    error: str | None = None
    response_headers: str = ""
    response_body: bytes = b""
    matched_indicators: list[str] = field(default_factory=list)
    in_scope: bool = True


def build_requests(template: dict, params: dict) -> list[ResolvedRequest]:
    resolved = []
    for i, req in enumerate(template.get("requests", []), start=1):
        headers = {
            render_text(k, params): sanitize_header_value(render_text(v, params))
            for k, v in req.get("headers", {}).items()
        }
        resolved.append(
            ResolvedRequest(
                index=i,
                name=req.get("name", f"Requête {i}"),
                method=req.get("method", "GET").upper(),
                url=render_text(req.get("url", ""), params),
                headers=headers,
                body=render_text(req.get("body", ""), params),
            )
        )
    return resolved


def host_in_scope(url: str, scope_entries: list[str]) -> bool:
    if not scope_entries:
        return False
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    for entry in scope_entries:
        e = entry.strip().lower().lstrip("*").lstrip(".")
        if not e:
            continue
        if host == e or host.endswith("." + e) or host.endswith(e):
            return True
    return False


def match_indicators(indicators: list[str], response_headers: str, response_body: bytes) -> list[str]:
    if not indicators:
        return []
    haystack = (response_headers + "\n" + response_body.decode("utf-8", errors="replace")).lower()
    return [ind for ind in indicators if ind.lower() in haystack]


# ==============================================================================
# 4. EXÉCUTION RÉSEAU (PYCURL)
# ==============================================================================
def send_with_pycurl(req: ResolvedRequest, timeout: int, verify_ssl: bool,
                      extra_headers: dict, auth_token: str) -> None:
    """Exécute une ResolvedRequest via PycURL et remplit ses champs de résultat en place."""
    body_buf = BytesIO()
    header_buf = BytesIO()
    c = pycurl.Curl()
    try:
        c.setopt(c.URL, req.url)
        c.setopt(c.WRITEDATA, body_buf)
        c.setopt(c.HEADERFUNCTION, header_buf.write)
        c.setopt(c.TIMEOUT, timeout)
        c.setopt(c.CONNECTTIMEOUT, min(timeout, 15))
        c.setopt(c.SSL_VERIFYPEER, 1 if verify_ssl else 0)
        c.setopt(c.SSL_VERIFYHOST, 2 if verify_ssl else 0)
        c.setopt(c.FOLLOWLOCATION, True)
        c.setopt(c.MAXREDIRS, 5)
        c.setopt(c.USERAGENT, "RTK-Request-Studio/1.0 (authorized-engagement)")

        headers = dict(req.headers)
        headers.update({k: sanitize_header_value(v) for k, v in extra_headers.items() if v})
        if auth_token:
            headers.setdefault("Authorization", f"Bearer {auth_token}")
        header_list = [f"{k}: {v}" for k, v in headers.items()]
        if header_list:
            c.setopt(c.HTTPHEADER, header_list)

        method = req.method.upper()
        body_bytes = req.body.encode("utf-8") if req.body else b""
        if method == "GET":
            pass
        elif method == "HEAD":
            c.setopt(c.NOBODY, True)
        elif method == "POST":
            c.setopt(c.POST, 1)
            c.setopt(c.POSTFIELDS, body_bytes)
        elif method == "PUT" and body_bytes:
            upload_buf = BytesIO(body_bytes)
            c.setopt(c.UPLOAD, 1)
            c.setopt(c.READDATA, upload_buf)
            c.setopt(c.INFILESIZE, len(body_bytes))
            c.setopt(c.CUSTOMREQUEST, "PUT")
        else:
            c.setopt(c.CUSTOMREQUEST, method)
            if body_bytes:
                c.setopt(c.POSTFIELDS, body_bytes)

        t0 = time.time()
        c.perform()
        req.status = c.getinfo(c.RESPONSE_CODE)
        req.elapsed = c.getinfo(c.TOTAL_TIME) or (time.time() - t0)
        req.error = None
    except pycurl.error as e:
        req.status = None
        req.elapsed = None
        req.error = f"pycurl error {e.args[0]}: {e.args[1] if len(e.args) > 1 else ''}"
    finally:
        c.close()
        req.response_headers = header_buf.getvalue().decode("utf-8", errors="replace")
        req.response_body = body_buf.getvalue()


# ==============================================================================
# 5. WIDGETS PERSONNALISÉS
# ==============================================================================
class Badge(tk.Label):
    def __init__(self, parent, text: str, color: str, **kw):
        super().__init__(
            parent, text=f" {text.upper()} ", bg=color, fg="#0f1420",
            font=("Segoe UI", 8, "bold"), padx=4, pady=1, **kw,
        )


class LabeledEntry(ttk.Frame):
    def __init__(self, parent, label: str, default: str = "", width: int = 42, show=None):
        super().__init__(parent, style="Panel.TFrame")
        ttk.Label(self, text=label, style="Field.TLabel").pack(anchor="w")
        self.var = tk.StringVar(value=default)
        self.entry = tk.Entry(
            self, textvariable=self.var, width=width, show=show,
            bg=BG_INPUT, fg=FG_TEXT, insertbackground=FG_TEXT,
            relief="flat", highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=ACCENT,
        )
        self.entry.pack(fill="x", pady=(2, 8))

    def get(self) -> str:
        return self.var.get().strip()


class TemplateCard(ttk.Frame):
    def __init__(self, parent, template: dict, on_click):
        super().__init__(parent, style="Card.TFrame", padding=10)
        self.template = template
        top = ttk.Frame(self, style="Card.TFrame")
        top.pack(fill="x")
        ttk.Label(top, text=template["name"], style="CardTitle.TLabel",
                  wraplength=230, justify="left").pack(side="left", anchor="w")
        Badge(self, template.get("severity", "info"),
              severity_color(template.get("severity", ""))).pack(anchor="w", pady=(4, 0))
        ttk.Label(self, text=template.get("rtk_module", ""), style="CardMeta.TLabel").pack(anchor="w", pady=(4, 0))
        for w in (self, top):
            w.bind("<Button-1>", lambda e: on_click(template))
        for child in self.winfo_children():
            child.bind("<Button-1>", lambda e: on_click(template))


# ==============================================================================
# 6. APPLICATION PRINCIPALE
# ==============================================================================
class RTKRequestStudio(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RTK Request Studio — PycURL Edition")
        self.geometry("1360x860")
        self.configure(bg=BG_ROOT)
        self._setup_style()

        try:
            self.templates = load_templates()
        except Exception as e:
            messagebox.showerror("Erreur de chargement", str(e))
            self.destroy()
            return

        self.current_template: dict | None = None
        self.param_entries: dict[str, LabeledEntry] = {}
        self.resolved_requests: list[ResolvedRequest] = []
        self.result_queue: "queue.Queue" = queue.Queue()
        self.sending = False

        self._build_layout()
        if self.templates:
            self._select_template(self.templates[0])
        self.bind("<F5>", lambda e: self._reload_library())
        self.after(150, self._poll_queue)

    # ---------------------------------------------------------------- style
    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure("PanelAlt.TFrame", background=BG_PANEL_ALT)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("Root.TFrame", background=BG_ROOT)
        style.configure("Field.TLabel", background=BG_PANEL, foreground=FG_MUTED, font=("Segoe UI", 9))
        style.configure("CardTitle.TLabel", background=BG_CARD, foreground=FG_TEXT, font=("Segoe UI", 10, "bold"))
        style.configure("CardMeta.TLabel", background=BG_CARD, foreground=FG_SUBTLE, font=("Segoe UI", 8))
        style.configure("Header.TLabel", background=BG_ROOT, foreground=FG_TEXT, font=("Segoe UI", 15, "bold"))
        style.configure("Sub.TLabel", background=BG_ROOT, foreground=FG_MUTED, font=("Segoe UI", 9))
        style.configure("TNotebook", background=BG_ROOT, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_PANEL, foreground=FG_MUTED, padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", BG_CARD)], foreground=[("selected", ACCENT)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#0f1420",
                         font=("Segoe UI", 10, "bold"), padding=8)
        style.map("Accent.TButton", background=[("active", ACCENT_DARK)])
        style.configure("Ghost.TButton", background=BG_PANEL_ALT, foreground=FG_TEXT, padding=6)
        style.configure("Treeview", background=BG_INPUT, fieldbackground=BG_INPUT,
                         foreground=FG_TEXT, borderwidth=0, rowheight=24)
        style.configure("Treeview.Heading", background=BG_PANEL_ALT, foreground=FG_MUTED, relief="flat")
        style.map("Treeview", background=[("selected", BG_CARD_HOVER)])
        style.configure("TCheckbutton", background=BG_PANEL, foreground=FG_TEXT)

    # --------------------------------------------------------------- layout
    def _build_layout(self):
        header = ttk.Frame(self, style="Root.TFrame", padding=(16, 12))
        header.pack(fill="x")
        ttk.Label(header, text="🛰  RTK Request Studio", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="Client HTTP instrumenté (PycURL) pour les sondes de vérification RTK — "
                               "engagements autorisés uniquement.",
                  style="Sub.TLabel").pack(anchor="w")
        if not PYCURL_AVAILABLE:
            warn = tk.Label(header, bg=WARN, fg="#1a1300",
                             text=" ⚠ PycURL n'est pas installé : mode aperçu seul (aucun envoi possible). "
                                  "Installez-le avec : pip install pycurl --break-system-packages ",
                             font=("Segoe UI", 9, "bold"), pady=4)
            warn.pack(fill="x", pady=(8, 0))

        body = ttk.Frame(self, style="Root.TFrame")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        sidebar = ttk.Frame(body, style="Panel.TFrame", width=280, padding=10)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="Bibliothèque d'attaques", style="Field.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(sidebar, textvariable=self.search_var, bg=BG_INPUT, fg=FG_TEXT,
                                 insertbackground=FG_TEXT, relief="flat", highlightthickness=1,
                                 highlightbackground=BORDER)
        search_entry.pack(fill="x", pady=8)
        self.search_var.trace_add("write", lambda *a: self._refresh_card_list())

        self.card_canvas_frame = ttk.Frame(sidebar, style="Panel.TFrame")
        self.card_canvas_frame.pack(fill="both", expand=True)
        self._refresh_card_list()

        main = ttk.Frame(body, style="Root.TFrame")
        main.pack(side="left", fill="both", expand=True, padx=(12, 0))

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill="both", expand=True)

        self.tab_config = ttk.Frame(self.notebook, style="Panel.TFrame", padding=14)
        self.tab_requests = ttk.Frame(self.notebook, style="Panel.TFrame", padding=14)
        self.tab_run = ttk.Frame(self.notebook, style="Panel.TFrame", padding=14)
        self.tab_report = ttk.Frame(self.notebook, style="Panel.TFrame", padding=14)
        self.notebook.add(self.tab_config, text="1 · Paramètres & périmètre")
        self.notebook.add(self.tab_requests, text="2 · Requêtes générées")
        self.notebook.add(self.tab_run, text="3 · Exécution & résultats")
        self.notebook.add(self.tab_report, text="4 · Log & rapport")

        self._build_tab_config()
        self._build_tab_requests()
        self._build_tab_run()
        self._build_tab_report()

    # ------------------------------------------------------- sidebar cards
    def _refresh_card_list(self):
        for w in self.card_canvas_frame.winfo_children():
            w.destroy()
        q = self.search_var.get().lower().strip()
        for t in self.templates:
            hay = f"{t['name']} {t.get('category','')} {t.get('rtk_module','')}".lower()
            if q and q not in hay:
                continue
            card = TemplateCard(self.card_canvas_frame, t, self._select_template)
            card.pack(fill="x", pady=4)

    def _select_template(self, template: dict):
        self.current_template = template
        self._build_param_form()
        self.title(f"RTK Request Studio — {template['name']}")

    def _reload_library(self):
        try:
            self.templates = load_templates()
            self._refresh_card_list()
            messagebox.showinfo("Rechargé", "Bibliothèque de templates rechargée depuis attack_templates.json.")
        except Exception as e:
            messagebox.showerror("Erreur de rechargement", str(e))

    # ------------------------------------------------------------ tab 1
    def _build_tab_config(self):
        top = ttk.Frame(self.tab_config, style="Panel.TFrame")
        top.pack(fill="x")
        self.engagement_id = LabeledEntry(top, "ID d'engagement (obligatoire)", "ENG-2026-LAB", width=30)
        self.engagement_id.pack(side="left", padx=(0, 16))
        self.operator_name = LabeledEntry(top, "Opérateur (obligatoire)", "", width=30)
        self.operator_name.pack(side="left", padx=(0, 16))
        self.timeout_entry = LabeledEntry(top, "Timeout (s)", "15", width=10)
        self.timeout_entry.pack(side="left", padx=(0, 16))

        opts = ttk.Frame(self.tab_config, style="Panel.TFrame")
        opts.pack(fill="x", pady=(0, 10))
        self.verify_ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Vérifier le certificat TLS", variable=self.verify_ssl_var).pack(side="left")
        self.auth_token = LabeledEntry(opts, "Jeton Authorization: Bearer (optionnel)", "", width=40)
        self.auth_token.pack(side="left", padx=(20, 0))

        ttk.Label(self.tab_config,
                  text="Périmètre autorisé — un domaine ou suffixe par ligne (ex: *.run.app, example.com).\n"
                       "Toute requête générée dont l'hôte cible ne correspond à aucune entrée sera IGNORÉE à l'envoi.",
                  style="Field.TLabel", justify="left").pack(anchor="w", pady=(6, 2))
        self.scope_text = tk.Text(self.tab_config, height=4, bg=BG_INPUT, fg=FG_TEXT,
                                   insertbackground=FG_TEXT, relief="flat", highlightthickness=1,
                                   highlightbackground=BORDER)
        self.scope_text.pack(fill="x")

        ttk.Label(self.tab_config, text="En-têtes globaux additionnels — un par ligne, format Clé: Valeur",
                  style="Field.TLabel").pack(anchor="w", pady=(10, 2))
        self.extra_headers_text = tk.Text(self.tab_config, height=3, bg=BG_INPUT, fg=FG_TEXT,
                                           insertbackground=FG_TEXT, relief="flat", highlightthickness=1,
                                           highlightbackground=BORDER)
        self.extra_headers_text.pack(fill="x")

        self.confirm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self.tab_config,
            text="Je confirme opérer dans le cadre d'un engagement de sécurité autorisé, "
                 "contre un périmètre que je suis mandaté à tester.",
            variable=self.confirm_var,
        ).pack(anchor="w", pady=(14, 4))

        ttk.Label(self.tab_config, text="Paramètres du scénario sélectionné", style="Field.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(16, 4))
        self.param_form_frame = ttk.Frame(self.tab_config, style="Panel.TFrame")
        self.param_form_frame.pack(fill="x")

        ttk.Button(self.tab_config, text="⚙ Générer les requêtes", style="Accent.TButton",
                   command=self._on_generate).pack(anchor="w", pady=(18, 0))

    def _build_param_form(self):
        for w in self.param_form_frame.winfo_children():
            w.destroy()
        self.param_entries = {}
        if not self.current_template:
            return
        row = ttk.Frame(self.param_form_frame, style="Panel.TFrame")
        row.pack(fill="x")
        for i, p in enumerate(self.current_template.get("parameters", [])):
            entry = LabeledEntry(row, p["label"], p.get("default", ""), width=36)
            entry.grid(row=i // 3, column=i % 3, padx=(0, 16), sticky="w")
            self.param_entries[p["key"]] = entry

    # ------------------------------------------------------------ tab 2
    def _build_tab_requests(self):
        cols = ("idx", "name", "method", "url")
        self.req_tree = ttk.Treeview(self.tab_requests, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (40, 260, 70, 480)):
            self.req_tree.heading(c, text=c.upper())
            self.req_tree.column(c, width=w, anchor="w")
        self.req_tree.pack(fill="x")
        self.req_tree.bind("<<TreeviewSelect>>", self._on_select_request)

        detail = ttk.Frame(self.tab_requests, style="Panel.TFrame")
        detail.pack(fill="both", expand=True, pady=(10, 0))
        ttk.Label(detail, text="Détail de la requête sélectionnée (en-têtes puis corps) — éditable avant envoi",
                  style="Field.TLabel").pack(anchor="w")
        self.req_detail_text = tk.Text(detail, bg=BG_INPUT, fg=FG_TEXT, insertbackground=FG_TEXT,
                                        relief="flat", highlightthickness=1, highlightbackground=BORDER)
        self.req_detail_text.pack(fill="both", expand=True, pady=(4, 8))
        ttk.Button(detail, text="💾 Appliquer la modification à cette requête", style="Ghost.TButton",
                   command=self._apply_request_edit).pack(anchor="w")

    def _on_select_request(self, _evt=None):
        sel = self.req_tree.selection()
        if not sel:
            return
        idx = int(self.req_tree.item(sel[0])["values"][0]) - 1
        req = self.resolved_requests[idx]
        headers_txt = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
        content = f"[HEADERS]\n{headers_txt}\n\n[BODY]\n{req.body}"
        self.req_detail_text.delete("1.0", "end")
        self.req_detail_text.insert("1.0", content)

    def _apply_request_edit(self):
        sel = self.req_tree.selection()
        if not sel:
            return
        idx = int(self.req_tree.item(sel[0])["values"][0]) - 1
        raw = self.req_detail_text.get("1.0", "end")
        try:
            headers_part, body_part = raw.split("[BODY]", 1)
        except ValueError:
            messagebox.showwarning("Format invalide", "Conservez les sections [HEADERS] et [BODY].")
            return
        headers_lines = headers_part.replace("[HEADERS]", "").strip().splitlines()
        new_headers = {}
        for line in headers_lines:
            if ":" in line:
                k, v = line.split(":", 1)
                new_headers[k.strip()] = sanitize_header_value(v.strip())
        self.resolved_requests[idx].headers = new_headers
        self.resolved_requests[idx].body = body_part.strip()
        messagebox.showinfo("OK", f"Requête #{idx + 1} mise à jour.")

    # ------------------------------------------------------------ tab 3
    def _build_tab_run(self):
        bar = ttk.Frame(self.tab_run, style="Panel.TFrame")
        bar.pack(fill="x")
        self.send_btn = ttk.Button(bar, text="▶ Envoyer toutes les requêtes", style="Accent.TButton",
                                    command=self._on_send_all)
        self.send_btn.pack(side="left")
        if not PYCURL_AVAILABLE:
            self.send_btn.state(["disabled"])
        ttk.Button(bar, text="🧹 Effacer les résultats", style="Ghost.TButton",
                   command=self._clear_results).pack(side="left", padx=8)
        self.progress_label = ttk.Label(bar, text="", style="Field.TLabel")
        self.progress_label.pack(side="left", padx=16)

        cols = ("idx", "name", "status", "elapsed", "indicators", "scope")
        self.result_tree = ttk.Treeview(self.tab_run, columns=cols, show="headings", height=10)
        headers_map = {"idx": "#", "name": "Requête", "status": "Statut", "elapsed": "Temps (s)",
                       "indicators": "Indicateurs trouvés", "scope": "Périmètre"}
        widths = (30, 260, 70, 80, 300, 90)
        for c, w in zip(cols, widths):
            self.result_tree.heading(c, text=headers_map[c])
            self.result_tree.column(c, width=w, anchor="w")
        self.result_tree.pack(fill="x", pady=(10, 0))
        self.result_tree.tag_configure("hit", background="#3a1f24", foreground=CRIT)
        self.result_tree.tag_configure("skip", foreground=FG_SUBTLE)
        self.result_tree.tag_configure("err", foreground=WARN)

        ttk.Label(self.tab_run, text="Journal en direct", style="Field.TLabel").pack(anchor="w", pady=(12, 2))
        self.live_log = tk.Text(self.tab_run, height=14, bg=BG_INPUT, fg=FG_TEXT, relief="flat",
                                 highlightthickness=1, highlightbackground=BORDER)
        self.live_log.pack(fill="both", expand=True)

    # ------------------------------------------------------------ tab 4
    def _build_tab_report(self):
        bar = ttk.Frame(self.tab_report, style="Panel.TFrame")
        bar.pack(fill="x")
        ttk.Button(bar, text="💾 Exporter le log (.jsonl)", style="Ghost.TButton",
                   command=self._export_jsonl).pack(side="left")
        ttk.Button(bar, text="📄 Générer le rapport Markdown", style="Ghost.TButton",
                   command=self._export_markdown).pack(side="left", padx=8)
        ttk.Button(bar, text="📋 Copier le rapport", style="Ghost.TButton",
                   command=self._copy_report).pack(side="left")

        self.report_text = tk.Text(self.tab_report, bg=BG_INPUT, fg=FG_TEXT, relief="flat",
                                    highlightthickness=1, highlightbackground=BORDER)
        self.report_text.pack(fill="both", expand=True, pady=(10, 0))

    # ---------------------------------------------------------- actions
    def _on_generate(self):
        if not self.current_template:
            return
        params = {k: e.get() for k, e in self.param_entries.items()}
        self.resolved_requests = build_requests(self.current_template, params)
        self.req_tree.delete(*self.req_tree.get_children())
        for r in self.resolved_requests:
            self.req_tree.insert("", "end", values=(r.index, r.name, r.method, r.url))
        self.result_tree.delete(*self.result_tree.get_children())
        self.notebook.select(self.tab_requests)
        self._log_live(f"[{self._ts()}] {len(self.resolved_requests)} requête(s) générée(s) "
                        f"pour le scénario « {self.current_template['name']} ».")

    def _preflight_checks(self) -> bool:
        if not PYCURL_AVAILABLE:
            messagebox.showwarning("PycURL indisponible", "Installez pycurl pour pouvoir envoyer des requêtes.")
            return False
        if not self.resolved_requests:
            messagebox.showwarning("Rien à envoyer", "Générez d'abord les requêtes (onglet 1).")
            return False
        if not self.engagement_id.get() or not self.operator_name.get():
            messagebox.showwarning("Champs requis", "Renseignez l'ID d'engagement et l'opérateur (onglet 1).")
            return False
        if not self.confirm_var.get():
            messagebox.showwarning("Confirmation requise",
                                    "Cochez la case de confirmation d'engagement autorisé (onglet 1).")
            return False
        scope_entries = [l for l in self.scope_text.get("1.0", "end").splitlines() if l.strip()]
        if not scope_entries:
            messagebox.showwarning("Périmètre requis",
                                    "Déclarez au moins une entrée de périmètre autorisé (onglet 1).")
            return False
        return True

    def _on_send_all(self):
        if self.sending or not self._preflight_checks():
            return
        self.sending = True
        self.send_btn.state(["disabled"])
        self.result_tree.delete(*self.result_tree.get_children())
        scope_entries = [l for l in self.scope_text.get("1.0", "end").splitlines() if l.strip()]
        extra_headers = {}
        for line in self.extra_headers_text.get("1.0", "end").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                extra_headers[k.strip()] = v.strip()
        try:
            timeout = int(self.timeout_entry.get() or "15")
        except ValueError:
            timeout = 15
        verify_ssl = self.verify_ssl_var.get()
        auth_token = self.auth_token.get()
        requests_snapshot = list(self.resolved_requests)

        t = threading.Thread(
            target=self._worker_send,
            args=(requests_snapshot, scope_entries, timeout, verify_ssl, extra_headers, auth_token),
            daemon=True,
        )
        t.start()

    def _worker_send(self, requests_list, scope_entries, timeout, verify_ssl, extra_headers, auth_token):
        indicators = self.current_template.get("indicators", []) if self.current_template else []
        for req in requests_list:
            req.in_scope = host_in_scope(req.url, scope_entries)
            if not req.in_scope:
                self.result_queue.put(("skip", req))
                continue
            send_with_pycurl(req, timeout, verify_ssl, extra_headers, auth_token)
            req.matched_indicators = match_indicators(indicators, req.response_headers, req.response_body)
            self.result_queue.put(("done", req))
        self.result_queue.put(("finished", None))

    def _poll_queue(self):
        try:
            while True:
                kind, req = self.result_queue.get_nowait()
                if kind == "finished":
                    self.sending = False
                    self.send_btn.state(["!disabled"])
                    self.progress_label.config(text="Terminé.")
                    self._generate_report_preview()
                    continue
                self._handle_result(kind, req)
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _handle_result(self, kind: str, req: ResolvedRequest):
        if kind == "skip":
            self.result_tree.insert("", "end", tags=("skip",),
                                     values=(req.index, req.name, "—", "—", "hors périmètre", "❌ ignorée"))
            self._log_live(f"[{self._ts()}] #{req.index} {req.name} — HORS PÉRIMÈTRE, requête ignorée ({req.url}).")
            return
        tag = ()
        status_disp = req.status if req.status is not None else f"ERR: {req.error}"
        if req.error:
            tag = ("err",)
        elif req.matched_indicators:
            tag = ("hit",)
        self.result_tree.insert(
            "", "end", tags=tag,
            values=(req.index, req.name, status_disp,
                    f"{req.elapsed:.3f}" if req.elapsed else "—",
                    ", ".join(req.matched_indicators) or "—", "✅ dans le périmètre"),
        )
        flag = " ⚠ INDICATEUR TROUVÉ" if req.matched_indicators else ""
        self._log_live(f"[{self._ts()}] #{req.index} {req.name} -> {status_disp} "
                        f"({req.elapsed:.3f}s){flag}" if req.elapsed else
                        f"[{self._ts()}] #{req.index} {req.name} -> ERREUR: {req.error}")

    def _clear_results(self):
        self.result_tree.delete(*self.result_tree.get_children())
        self.live_log.delete("1.0", "end")

    # ---------------------------------------------------------- reporting
    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _log_live(self, line: str):
        self.live_log.insert("end", line + "\n")
        self.live_log.see("end")

    def _export_jsonl(self):
        if not self.resolved_requests:
            return
        path = filedialog.asksaveasfilename(defaultextension=".jsonl",
                                             filetypes=[("JSON Lines", "*.jsonl")],
                                             initialfile=f"{self.current_template['id']}_log.jsonl")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for r in self.resolved_requests:
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "engagement_id": self.engagement_id.get(),
                    "operator": self.operator_name.get(),
                    "scenario_id": self.current_template["id"],
                    "request_name": r.name,
                    "method": r.method,
                    "url": r.url,
                    "request_headers": r.headers,
                    "request_body": r.body,
                    "in_scope": r.in_scope,
                    "status": r.status,
                    "elapsed_s": r.elapsed,
                    "error": r.error,
                    "response_headers": r.response_headers,
                    "response_body_preview": r.response_body[:4000].decode("utf-8", errors="replace"),
                    "matched_indicators": r.matched_indicators,
                }
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        messagebox.showinfo("Exporté", f"Log JSONL enregistré :\n{path}")

    def _generate_report_preview(self):
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", self._build_markdown_report())
        self.notebook.select(self.tab_report)

    def _build_markdown_report(self) -> str:
        t = self.current_template or {}
        lines = [
            f"# Rapport de sondes — {t.get('name', '')}",
            "",
            f"- **Engagement** : {self.engagement_id.get() or '(non renseigné)'}",
            f"- **Opérateur** : {self.operator_name.get() or '(non renseigné)'}",
            f"- **Horodatage** : {datetime.now().isoformat(timespec='seconds')}",
            f"- **Module RTK** : {t.get('rtk_module', '')}",
            f"- **Sévérité déclarée** : {t.get('severity', '')}",
            "",
            "## Références",
            "- OWASP : " + ", ".join(t.get("owasp", [])) if t.get("owasp") else "- OWASP : —",
            "- MITRE ATT&CK : " + ", ".join(t.get("mitre_attack", [])) if t.get("mitre_attack") else "- MITRE ATT&CK : —",
            "",
            "## Résultats",
            "",
            "| # | Requête | Statut | Temps (s) | Indicateurs trouvés |",
            "|---|---|---|---|---|",
        ]
        for r in self.resolved_requests:
            status = r.status if r.status is not None else (f"ERR: {r.error}" if r.error else "non envoyée / hors périmètre")
            elapsed = f"{r.elapsed:.3f}" if r.elapsed else "—"
            indic = ", ".join(r.matched_indicators) if r.matched_indicators else "—"
            lines.append(f"| {r.index} | {r.name} | {status} | {elapsed} | {indic} |")
        lines += ["", "## Détail des requêtes", ""]
        for r in self.resolved_requests:
            lines.append(f"### #{r.index} — {r.name}")
            lines.append(f"`{r.method} {r.url}`")
            lines.append("")
            lines.append("```")
            lines.append("\n".join(f"{k}: {v}" for k, v in r.headers.items()))
            if r.body:
                lines.append("")
                lines.append(r.body)
            lines.append("```")
            if r.response_headers:
                lines.append("")
                lines.append("Réponse (en-têtes, extrait) :")
                lines.append("```")
                lines.append(r.response_headers.strip()[:1500])
                lines.append("```")
            lines.append("")
        return "\n".join(lines)

    def _export_markdown(self):
        if not self.resolved_requests:
            messagebox.showwarning("Rien à exporter", "Générez puis envoyez des requêtes d'abord.")
            return
        content = self._build_markdown_report()
        path = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown", "*.md")],
                                             initialfile=f"rapport_{self.current_template['id']}.md")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", content)
        messagebox.showinfo("Exporté", f"Rapport Markdown enregistré :\n{path}")

    def _copy_report(self):
        content = self.report_text.get("1.0", "end").strip()
        if not content:
            content = self._build_markdown_report()
        self.clipboard_clear()
        self.clipboard_append(content)


def main():
    app = RTKRequestStudio()
    if app.winfo_exists():
        app.mainloop()


if __name__ == "__main__":
    main()
