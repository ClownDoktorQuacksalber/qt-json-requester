import json
import os
import re
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, Tuple

import requests
from qtpy import QtCore, QtWidgets

APP_TITLE = "QtPy JSON Client (GET/POST + NGINX BasicAuth + Website Login)"
CONFIG_FILE = "configs.json"


@dataclass
class RequestConfig:
    name: str
    url: str
    method: str = "GET"  # GET or POST

    # NGINX Basic Auth
    nginx_username: str = ""
    nginx_password: str = ""

    # Website Login (Session)
    site_login_url: str = ""
    site_username: str = ""
    site_password: str = ""
    site_username_field: str = "login"      # in deinem JSON: login
    site_password_field: str = "password"   # in deinem JSON: password
    csrf_cookie_name: str = "csrftoken"
    csrf_form_field: str = "csrfmiddlewaretoken"

    headers_json: str = "{\n  \"Accept\": \"application/json\"\n}"
    params_json: str = "{}"
    body_json: str = "{}"
    timeout_s: int = 30
    verify_ssl: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "RequestConfig":
        return RequestConfig(
            name=d.get("name", ""),
            url=d.get("url", ""),
            method=d.get("method", "GET"),

            nginx_username=d.get("nginx_username", ""),
            nginx_password=d.get("nginx_password", ""),

            site_login_url=d.get("site_login_url", ""),
            site_username=d.get("site_username", ""),
            site_password=d.get("site_password", ""),
            site_username_field=d.get("site_username_field", "login"),
            site_password_field=d.get("site_password_field", "password"),
            csrf_cookie_name=d.get("csrf_cookie_name", "csrftoken"),
            csrf_form_field=d.get("csrf_form_field", "csrfmiddlewaretoken"),

            headers_json=d.get("headers_json", "{\n  \"Accept\": \"application/json\"\n}"),
            params_json=d.get("params_json", "{}"),
            body_json=d.get("body_json", "{}"),
            timeout_s=int(d.get("timeout_s", 30)),
            verify_ssl=bool(d.get("verify_ssl", True)),
        )



def load_configs(path: str) -> Dict[str, RequestConfig]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        out: Dict[str, RequestConfig] = {}
        for name, cfg in raw.items():
            out[name] = RequestConfig.from_dict(cfg)
        return out
    except Exception:
        return {}


def save_configs(path: str, configs: Dict[str, RequestConfig]) -> None:
    raw = {name: cfg.to_dict() for name, cfg in configs.items()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(raw, f, ensure_ascii=False, indent=2)


def parse_json_text(text: str, label: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {}
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
        raise ValueError(f"{label} muss ein JSON-Objekt ({{...}}) sein.")
    except json.JSONDecodeError as e:
        raise ValueError(f"{label} ist kein gültiges JSON: {e}") from e


def extract_csrf_from_html(html: str, field_name: str) -> Optional[str]:
    """
    Sucht nach: <input type="hidden" name="csrfmiddlewaretoken" value="...">
    """
    if not html:
        return None
    pattern = rf'name="{re.escape(field_name)}"\s+value="([^"]+)"'
    m = re.search(pattern, html)
    return m.group(1) if m else None


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1250, 760)

        self.configs: Dict[str, RequestConfig] = load_configs(CONFIG_FILE)

        # Eine Session pro App (Cookies bleiben erhalten)
        self.session = requests.Session()

        # --- Left: saved list ---
        self.list_widget = QtWidgets.QListWidget()
        self.list_widget.setMinimumWidth(260)
        self.list_widget.itemSelectionChanged.connect(self.on_select_saved)

        btn_new = QtWidgets.QPushButton("Neu")
        btn_save = QtWidgets.QPushButton("Speichern/Update")
        btn_delete = QtWidgets.QPushButton("Löschen")
        btn_clear_cookies = QtWidgets.QPushButton("Cookies reset")

        btn_new.clicked.connect(self.on_new)
        btn_save.clicked.connect(self.on_save)
        btn_delete.clicked.connect(self.on_delete)
        btn_clear_cookies.clicked.connect(self.on_clear_cookies)

        left_btns = QtWidgets.QHBoxLayout()
        left_btns.addWidget(btn_new)
        left_btns.addWidget(btn_save)
        left_btns.addWidget(btn_delete)

        left_layout = QtWidgets.QVBoxLayout()
        left_layout.addWidget(QtWidgets.QLabel("Gespeicherte Konfigurationen"))
        left_layout.addWidget(self.list_widget)
        left_layout.addLayout(left_btns)
        left_layout.addWidget(btn_clear_cookies)

        left_container = QtWidgets.QWidget()
        left_container.setLayout(left_layout)

        # --- Right: editor + response ---
        self.name_edit = QtWidgets.QLineEdit()
        self.url_edit = QtWidgets.QLineEdit()
        self.method_combo = QtWidgets.QComboBox()
        self.method_combo.addItems(["GET", "POST"])
        self.method_combo.currentTextChanged.connect(self.on_method_changed)

        # NGINX auth fields
        self.nginx_user_edit = QtWidgets.QLineEdit()
        self.nginx_pass_edit = QtWidgets.QLineEdit()
        self.nginx_pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        # Site login fields
        self.site_login_url_edit = QtWidgets.QLineEdit()
        self.site_user_edit = QtWidgets.QLineEdit()
        self.site_pass_edit = QtWidgets.QLineEdit()
        self.site_pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.site_user_field_edit = QtWidgets.QLineEdit("login")
        self.site_pass_field_edit = QtWidgets.QLineEdit("password")
        self.csrf_cookie_edit = QtWidgets.QLineEdit("csrftoken")
        self.csrf_field_edit = QtWidgets.QLineEdit("csrfmiddlewaretoken")

        self.login_btn = QtWidgets.QPushButton("Website-Login testen")
        self.login_btn.clicked.connect(self.on_site_login)

        self.timeout_spin = QtWidgets.QSpinBox()
        self.timeout_spin.setRange(1, 600)
        self.timeout_spin.setValue(30)

        self.verify_ssl_check = QtWidgets.QCheckBox("SSL verifizieren")
        self.verify_ssl_check.setChecked(True)

        self.headers_edit = QtWidgets.QPlainTextEdit()
        self.params_edit = QtWidgets.QPlainTextEdit()
        self.body_edit = QtWidgets.QPlainTextEdit()

        self.headers_edit.setPlainText("{\n  \"Accept\": \"application/json\"\n}")
        self.params_edit.setPlainText("{}")
        self.body_edit.setPlainText("{}")

        self.send_btn = QtWidgets.QPushButton("Senden")
        self.send_btn.clicked.connect(self.on_send)

        self.status_label = QtWidgets.QLabel("Bereit.")
        self.status_label.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)

        self.response_edit = QtWidgets.QPlainTextEdit()
        self.response_edit.setReadOnly(True)

        # Layout - Form
        form = QtWidgets.QFormLayout()
        form.addRow("Name:", self.name_edit)
        form.addRow("URL (API):", self.url_edit)
        form.addRow("Methode:", self.method_combo)

        # Group: NGINX
        nginx_group = QtWidgets.QGroupBox("NGINX Basic Auth (Reverse Proxy)")
        nginx_form = QtWidgets.QFormLayout()
        nginx_form.addRow("NGINX Username:", self.nginx_user_edit)
        nginx_form.addRow("NGINX Passwort:", self.nginx_pass_edit)
        nginx_group.setLayout(nginx_form)

        # Group: Website Login
        site_group = QtWidgets.QGroupBox("Website Login (Session/Cookies)")
        site_form = QtWidgets.QFormLayout()
        site_form.addRow("Login-URL:", self.site_login_url_edit)
        site_form.addRow("Website Username:", self.site_user_edit)
        site_form.addRow("Website Passwort:", self.site_pass_edit)

        fields_row = QtWidgets.QHBoxLayout()
        fields_row.addWidget(QtWidgets.QLabel("User-Field:"))
        fields_row.addWidget(self.site_user_field_edit)
        fields_row.addWidget(QtWidgets.QLabel("Pass-Field:"))
        fields_row.addWidget(self.site_pass_field_edit)
        fields_row.addSpacing(10)
        fields_row.addWidget(QtWidgets.QLabel("CSRF Cookie:"))
        fields_row.addWidget(self.csrf_cookie_edit)
        fields_row.addWidget(QtWidgets.QLabel("CSRF Field:"))
        fields_row.addWidget(self.csrf_field_edit)

        site_wrap = QtWidgets.QVBoxLayout()
        site_wrap.addLayout(site_form)
        site_wrap.addLayout(fields_row)
        site_wrap.addWidget(self.login_btn)
        site_group.setLayout(site_wrap)

        opts_row = QtWidgets.QHBoxLayout()
        opts_row.addWidget(QtWidgets.QLabel("Timeout (s):"))
        opts_row.addWidget(self.timeout_spin)
        opts_row.addSpacing(20)
        opts_row.addWidget(self.verify_ssl_check)
        opts_row.addStretch(1)

        top_wrap = QtWidgets.QVBoxLayout()
        top_wrap.addLayout(form)
        top_wrap.addWidget(nginx_group)
        top_wrap.addWidget(site_group)
        top_wrap.addLayout(opts_row)

        # JSON editor tabs
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self.headers_edit, "Headers (JSON)")
        self.tabs.addTab(self.params_edit, "Query Params (JSON)")
        self.tabs.addTab(self.body_edit, "Body (JSON)")

        right_layout = QtWidgets.QVBoxLayout()
        right_layout.addLayout(top_wrap)
        right_layout.addWidget(self.tabs)

        send_row = QtWidgets.QHBoxLayout()
        send_row.addWidget(self.send_btn)
        send_row.addWidget(self.status_label, 1)
        right_layout.addLayout(send_row)

        right_layout.addWidget(QtWidgets.QLabel("Antwort:"))
        right_layout.addWidget(self.response_edit, 1)

        right_container = QtWidgets.QWidget()
        right_container.setLayout(right_layout)

        splitter = QtWidgets.QSplitter()
        splitter.addWidget(left_container)
        splitter.addWidget(right_container)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        self.setCentralWidget(splitter)

        self.refresh_list()
        self.on_method_changed(self.method_combo.currentText())

    def refresh_list(self):
        self.list_widget.blockSignals(True)
        self.list_widget.clear()
        for name in sorted(self.configs.keys(), key=lambda s: s.lower()):
            self.list_widget.addItem(name)
        self.list_widget.blockSignals(False)

    def ensure_logged_in(self, cfg: RequestConfig) -> Tuple[bool, str]:
        """
        Stellt sicher, dass wir eine eingeloggte Session haben.
        Wenn keine Session vorhanden ist, wird automatisch perform_site_login() ausgeführt
        (sofern Login-URL + Credentials gesetzt sind).
        """
        cookie_names = {c.name for c in self.session.cookies}
        has_session = ("sessionid" in cookie_names) or any("session" in n.lower() for n in cookie_names)

        if has_session:
            return True, "Session bereits vorhanden."

        # Auto-Login nur wenn Daten vorhanden
        if cfg.site_login_url and cfg.site_username and cfg.site_password:
            ok, info = self.perform_site_login(cfg)
            return ok, info

        return False, "Keine Session vorhanden und keine Website-Login Daten gesetzt."

    def on_select_saved(self):
        items = self.list_widget.selectedItems()
        if not items:
            return
        name = items[0].text()
        cfg = self.configs.get(name)
        if cfg:
            self.load_into_form(cfg)

    def load_into_form(self, cfg: RequestConfig):
        self.name_edit.setText(cfg.name)
        self.url_edit.setText(cfg.url)
        self.method_combo.setCurrentText(cfg.method.upper())

        self.nginx_user_edit.setText(cfg.nginx_username)
        self.nginx_pass_edit.setText(cfg.nginx_password)

        self.site_login_url_edit.setText(cfg.site_login_url)
        self.site_user_edit.setText(cfg.site_username)
        self.site_pass_edit.setText(cfg.site_password)
        self.site_user_field_edit.setText(cfg.site_username_field)
        self.site_pass_field_edit.setText(cfg.site_password_field)
        self.csrf_cookie_edit.setText(cfg.csrf_cookie_name)
        self.csrf_field_edit.setText(cfg.csrf_form_field)

        self.headers_edit.setPlainText(cfg.headers_json or "{}")
        self.params_edit.setPlainText(cfg.params_json or "{}")
        self.body_edit.setPlainText(cfg.body_json or "{}")
        self.timeout_spin.setValue(int(cfg.timeout_s))
        self.verify_ssl_check.setChecked(bool(cfg.verify_ssl))

        self.on_method_changed(self.method_combo.currentText())

    def read_from_form(self) -> RequestConfig:
        return RequestConfig(
            name=self.name_edit.text().strip(),
            url=self.url_edit.text().strip(),
            method=self.method_combo.currentText().strip().upper(),

            nginx_username=self.nginx_user_edit.text(),
            nginx_password=self.nginx_pass_edit.text(),

            site_login_url=self.site_login_url_edit.text().strip(),
            site_username=self.site_user_edit.text(),
            site_password=self.site_pass_edit.text(),
            site_username_field=self.site_user_field_edit.text().strip() or "login",
            site_password_field=self.site_pass_field_edit.text().strip() or "password",
            csrf_cookie_name=self.csrf_cookie_edit.text().strip() or "csrftoken",
            csrf_form_field=self.csrf_field_edit.text().strip() or "csrfmiddlewaretoken",

            headers_json=self.headers_edit.toPlainText(),
            params_json=self.params_edit.toPlainText(),
            body_json=self.body_edit.toPlainText(),
            timeout_s=int(self.timeout_spin.value()),
            verify_ssl=bool(self.verify_ssl_check.isChecked()),
        )

    def on_new(self):
        self.list_widget.clearSelection()
        self.name_edit.clear()
        self.url_edit.clear()
        self.method_combo.setCurrentText("GET")

        self.nginx_user_edit.clear()
        self.nginx_pass_edit.clear()

        self.site_login_url_edit.clear()
        self.site_user_edit.clear()
        self.site_pass_edit.clear()
        self.site_user_field_edit.setText("login")
        self.site_pass_field_edit.setText("password")
        self.csrf_cookie_edit.setText("csrftoken")
        self.csrf_field_edit.setText("csrfmiddlewaretoken")

        self.headers_edit.setPlainText("{\n  \"Accept\": \"application/json\"\n}")
        self.params_edit.setPlainText("{}")
        self.body_edit.setPlainText("{}")
        self.timeout_spin.setValue(30)
        self.verify_ssl_check.setChecked(True)
        self.response_edit.clear()
        self.status_label.setText("Neuer Eintrag.")

    def on_save(self):
        cfg = self.read_from_form()
        if not cfg.name:
            self.status_label.setText("Fehler: Name fehlt.")
            return
        if not cfg.url:
            self.status_label.setText("Fehler: URL fehlt.")
            return
        try:
            _ = parse_json_text(cfg.headers_json, "Headers")
            _ = parse_json_text(cfg.params_json, "Query Params")
            if cfg.method == "POST":
                _ = parse_json_text(cfg.body_json, "Body")
        except ValueError as e:
            self.status_label.setText(f"Fehler: {e}")
            return

        self.configs[cfg.name] = cfg
        save_configs(CONFIG_FILE, self.configs)
        self.refresh_list()
        matches = self.list_widget.findItems(cfg.name, QtCore.Qt.MatchFlag.MatchExactly)
        if matches:
            self.list_widget.setCurrentItem(matches[0])
        self.status_label.setText(f"Gespeichert: {cfg.name}")

    def on_delete(self):
        items = self.list_widget.selectedItems()
        if not items:
            self.status_label.setText("Nichts ausgewählt.")
            return
        name = items[0].text()
        if name in self.configs:
            del self.configs[name]
            save_configs(CONFIG_FILE, self.configs)
            self.refresh_list()
            self.on_new()
            self.status_label.setText(f"Gelöscht: {name}")

    def on_clear_cookies(self):
        self.session.cookies.clear()
        self.status_label.setText("Cookies geleert (Session reset).")

    def on_method_changed(self, method: str):
        method = (method or "").upper()
        if method == "POST":
            self.tabs.setTabEnabled(self.tabs.indexOf(self.body_edit), True)
            self.body_edit.setEnabled(True)
        else:
            idx = self.tabs.indexOf(self.body_edit)
            self.tabs.setTabEnabled(idx, False)
            self.body_edit.setEnabled(False)

        # ensure other tabs enabled
        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if w is self.body_edit and method != "POST":
                self.tabs.setTabEnabled(i, False)
            else:
                self.tabs.setTabEnabled(i, True)

    def build_nginx_auth(self, cfg: RequestConfig) -> Optional[requests.auth.HTTPBasicAuth]:
        if cfg.nginx_username or cfg.nginx_password:
            return requests.auth.HTTPBasicAuth(cfg.nginx_username, cfg.nginx_password)
        return None

    def on_site_login(self):
        cfg = self.read_from_form()
        if not cfg.site_login_url:
            self.status_label.setText("Fehler: Login-URL fehlt.")
            return
        if not cfg.site_username or not cfg.site_password:
            self.status_label.setText("Fehler: Website Username/Passwort fehlt.")
            return

        self.login_btn.setEnabled(False)
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        self.status_label.setText("Website Login...")

        try:
            ok, info = self.perform_site_login(cfg)
            if ok:
                self.status_label.setText(f"Login OK. {info}")
            else:
                self.status_label.setText(f"Login FEHLER. {info}")
            self.response_edit.setPlainText(info)
        except Exception as e:
            self.status_label.setText("Login FEHLER (Exception).")
            self.response_edit.setPlainText(str(e))
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()
            self.login_btn.setEnabled(True)



    def perform_site_login(self, cfg: RequestConfig) -> Tuple[bool, str]:
        nginx_auth = self.build_nginx_auth(cfg)

        def cookie_names():
            return ", ".join(sorted({c.name for c in self.session.cookies}))

        # 1) GET Login (CSRF Cookie + HTML/JSON Token holen)
        r1 = self.session.get(
            cfg.site_login_url,
            auth=nginx_auth,
            timeout=cfg.timeout_s,
            verify=cfg.verify_ssl,
            headers={"Accept": "application/json,text/html;q=0.9,*/*;q=0.8"},
            allow_redirects=True,
        )

        csrf_cookie_val = self.session.cookies.get(cfg.csrf_cookie_name)
        csrf_token_from_form = None

        ct1 = r1.headers.get("Content-Type", "")
        if "application/json" in ct1:
            try:
                j = r1.json()
                html = j.get("html", "") if isinstance(j, dict) else ""
                csrf_token_from_form = extract_csrf_from_html(html, cfg.csrf_form_field)
            except Exception:
                pass
        else:
            csrf_token_from_form = extract_csrf_from_html(r1.text or "", cfg.csrf_form_field)

        # Django: Header nimmt Cookie, Form nimmt Hidden Token (oder Cookie falls kein Hidden)
        csrf_for_header = csrf_cookie_val or csrf_token_from_form
        csrf_for_form = csrf_token_from_form or csrf_cookie_val

        if not csrf_for_header or not csrf_for_form:
            return False, (
                "CSRF konnte nicht bestimmt werden.\n"
                f"GET {cfg.site_login_url} -> {r1.status_code} ({ct1})\n"
                f"CSRF Cookie {cfg.csrf_cookie_name}={csrf_cookie_val}\n"
                f"CSRF Form {cfg.csrf_form_field}={csrf_token_from_form}\n"
                f"Cookies: {cookie_names()}"
            )

        # 2) POST Login
        login_data = {
            cfg.csrf_form_field: csrf_for_form,
            cfg.site_username_field: cfg.site_username,
            cfg.site_password_field: cfg.site_password,
            "remember": "on",  # optional, schadet normalerweise nicht
        }

        headers = {
            "Referer": cfg.site_login_url,
            "X-CSRFToken": csrf_for_header,
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
        }

        r2 = self.session.post(
            cfg.site_login_url,
            data=login_data,
            headers=headers,
            auth=nginx_auth,
            timeout=cfg.timeout_s,
            verify=cfg.verify_ssl,
            allow_redirects=True,
        )

        # 3) JSON-Errors aus POST Antwort lesen (WICHTIG!)
        ct2 = r2.headers.get("Content-Type", "")
        post_errors = []
        post_form_errors = []

        if "application/json" in ct2:
            try:
                j2 = r2.json()
                if isinstance(j2, dict):
                    form = j2.get("form", {})
                    if isinstance(form, dict):
                        fe = form.get("errors", [])
                        if fe:
                            post_form_errors.append(f"form.errors={fe}")
                        fields = form.get("fields", {})
                        if isinstance(fields, dict):
                            for fname, fobj in fields.items():
                                ferr = (fobj or {}).get("errors", [])
                                if ferr:
                                    post_errors.append(f"{fname}.errors={ferr}")
            except Exception:
                pass

        # 4) Erfolg prüfen: sessionid Cookie?
        cookies_now = {c.name for c in self.session.cookies}
        has_session = ("sessionid" in cookies_now) or any("session" in n.lower() for n in cookies_now)

        # Debug-Block immer ausgeben, damit du siehst was wirklich passiert
        debug = (
            f"GET login:  {r1.status_code} | {ct1} | url={r1.url}\n"
            f"POST login: {r2.status_code} | {ct2} | url={r2.url}\n"
            f"POST Set-Cookie: {r2.headers.get('Set-Cookie','')}\n"
            f"Cookies danach: {cookie_names()}\n"
            f"CSRF cookie={cfg.csrf_cookie_name}={csrf_cookie_val}\n"
            f"CSRF form={cfg.csrf_form_field}={csrf_token_from_form}\n"
        )

        if post_form_errors or post_errors:
            return False, "Login FEHLER (Form Errors vom Server):\n" + "\n".join(post_form_errors + post_errors) + "\n\n" + debug

        if has_session:
            return True, "Login OK (Session Cookie vorhanden)\n\n" + debug

        # Fallback: Text/HTML sieht weiter nach Login aus
        txt = (r2.text or "")
        if "accounts/login" in txt or "Anmelden" in txt:
            return False, "Login FEHLER (weiterhin Login-Seite)\n\n" + debug

        return False, "Login unklar (kein Session Cookie, aber auch keine eindeutigen Errors)\n\n" + debug



    def on_send(self):
        cfg = self.read_from_form()
        if not cfg.url:
            self.status_label.setText("Fehler: URL fehlt.")
            return

        try:
            headers = parse_json_text(cfg.headers_json, "Headers")
            params = parse_json_text(cfg.params_json, "Query Params")
            body = parse_json_text(cfg.body_json, "Body") if cfg.method == "POST" else None
        except ValueError as e:
            self.status_label.setText(f"Fehler: {e}")
            return

        nginx_auth = self.build_nginx_auth(cfg)

        self.send_btn.setEnabled(False)
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        self.status_label.setText("Sende Anfrage...")

        try:
            # ✅ Auto-Login, falls nötig
            ok, info = self.ensure_logged_in(cfg)
            if not ok:
                self.status_label.setText("Nicht eingeloggt.")
                self.response_edit.setPlainText("Login fehlt:\n" + info)
                return

            # Anfrage senden
            resp = self.perform_request(
                method=cfg.method,
                url=cfg.url,
                headers=headers,
                params=params,
                json_body=body,
                nginx_auth=nginx_auth,
                timeout=cfg.timeout_s,
                verify_ssl=cfg.verify_ssl,
                cfg=cfg,
            )
            self.show_response(resp)

        except Exception as e:
            self.response_edit.setPlainText(str(e))
            self.status_label.setText("Fehler bei Anfrage.")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()
            self.send_btn.setEnabled(True)
            
    def perform_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, Any],
        params: Dict[str, Any],
        json_body: Optional[Dict[str, Any]],
        nginx_auth: Optional[requests.auth.HTTPBasicAuth],
        timeout: int,
        verify_ssl: bool,
        cfg: RequestConfig,
    ) -> requests.Response:
        method = method.upper().strip()

        # falls CSRF für API-POST nötig ist, automatisch setzen (Django)
        if method == "POST":
            csrf = self.session.cookies.get(cfg.csrf_cookie_name)
            if csrf and "X-CSRFToken" not in headers:
                headers["X-CSRFToken"] = csrf
            if "Referer" not in headers:
                headers["Referer"] = cfg.site_login_url or url

        if method == "GET":
            resp = self.session.get(url, headers=headers, params=params, auth=nginx_auth,
                                    timeout=timeout, verify=verify_ssl)

            ct = resp.headers.get("Content-Type", "")
            if "text/html" in ct.lower():
                # fallback: format=json probieren
                params2 = dict(params or {})
                params2.setdefault("format", "json")
                resp2 = self.session.get(url, headers=headers, params=params2, auth=nginx_auth,
                                         timeout=timeout, verify=verify_ssl)
                return resp2
            return resp
        elif method == "POST":
            return self.session.post(
                url,
                headers=headers,
                params=params,
                json=json_body if json_body is not None else {},
                auth=nginx_auth,
                timeout=timeout,
                verify=verify_ssl,
            )
        else:
            raise ValueError("Nur GET und POST werden unterstützt.")

    def show_response(self, resp: requests.Response):
        status = f"HTTP {resp.status_code}"
        ct = resp.headers.get("Content-Type", "")
        self.status_label.setText(f"{status} | {ct}")

        # Try pretty JSON
        text = resp.text or ""
        out = ""
        try:
            parsed = resp.json()
            out = json.dumps(parsed, ensure_ascii=False, indent=2)
        except Exception:
            out = text

        header_lines = [f"{k}: {v}" for k, v in resp.headers.items()]
        header_block = "\n".join(header_lines)

        cookie_line = "\n".join([f"{c.name}={c.value}" for c in self.session.cookies])

        self.response_edit.setPlainText(
            f"{status}\n\n--- Session Cookies ---\n{cookie_line}\n\n"
            f"--- Response Headers ---\n{header_block}\n\n--- Body ---\n{out}"
        )


def main():
    app = QtWidgets.QApplication([])
    w = MainWindow()
    w.show()
    app.exec()


if __name__ == "__main__":
    main()