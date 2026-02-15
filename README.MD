# QtPy JSON Client

Ein grafischer API-Client für **GET** und **POST JSON Requests** mit Support für:

* Session-Login (CSRF / Cookies)
* NGINX BasicAuth
* gespeicherte Request-Profile
* Header / Params / Body Editor
* automatische Session-Verwendung
* GUI auf Basis von **QtPy**

---

## ✨ Features

* 🔐 Website Login Simulation (inkl. CSRF Token Parsing)
* 🌐 Reverse Proxy Auth (NGINX BasicAuth)
* 💾 Konfigurationen speichern / laden
* 📡 JSON Requests senden und Antworten formatiert anzeigen
* 🔁 automatische Login-Erkennung + Session Reuse
* 🧠 erkennt Login-Responses statt JSON
* 🪟 Windows-Startscript mit Auto-venv Setup

---

## 📦 Installation

### Voraussetzungen

* Python ≥ 3.10
* Windows empfohlen (Batch Starter enthalten)

---

### Starten (empfohlen)

```bat
start.bat
```

Das Script erledigt automatisch:

* virtuelle Umgebung erstellen
* pip aktualisieren
* Dependencies installieren
* App starten

---

### Manuell starten

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

---

## ⚙️ Konfigurationen

Gespeicherte Requests werden in gespeichert:

```
configs.json
```

Diese Datei ist **nicht im Repo** (siehe `.gitignore`), da sie enthalten kann:

* Logins
* Tokens
* API URLs

Wenn du Beispiele bereitstellen willst:

```
configs.example.json
```

---

## 🔐 Authentifizierung

Der Client unterstützt gleichzeitig:

| Typ           | Beschreibung        |
| ------------- | ------------------- |
| NGINX Auth    | BasicAuth Header    |
| Website Login | Session Cookie      |
| CSRF          | automatisch erkannt |
| Session Reuse | Ja                  |

---

## 🧪 Typischer Workflow

1. Login URL eintragen
2. Website Login testen
3. API URL eintragen
4. JSON Request senden

Der Client:

* loggt dich ein
* speichert Cookies
* sendet API Request

---

## 🛠 Unterstützte Request Optionen

* Custom Headers
* Query Params
* JSON Body
* SSL Verification toggle
* Timeout Einstellung

---

## 📊 Response Anzeige

Die Antwort wird angezeigt mit:

* HTTP Status
* Response Header
* Session Cookies
* JSON Pretty Print (wenn möglich)
* Raw Body fallback

---

## 🧩 Architektur

```
Qt GUI
   ↓
RequestConfig (Model)
   ↓
Requests.Session()
   ↓
Server API
```

---

## 🐞 Troubleshooting

### 500 Error statt JSON

→ Server sendet HTML Fehlerseite statt JSON
→ meist Berechtigungsproblem oder falscher Header

---

### Login funktioniert im Browser aber nicht im Client

Meist fehlt einer dieser Header:

```
X-Requested-With: XMLHttpRequest
Referer: <login-url>
Accept: application/json
```

---

### SSL Fehler

→ SSL Verify deaktivieren

---

## 📁 Projektstruktur

```
project/
│
├── app.py
├── start.bat
├── requirements.txt
├── configs.example.json
├── README.md
└── .gitignore
```

---

## 🔒 Sicherheit

Dieses Tool speichert:

* Zugangsdaten
* Tokens
* Cookies

👉 Deshalb:

* configs.json niemals committen
* Repo nur mit Beispielconfig veröffentlichen

---

## 🧑‍💻 Entwickler Hinweise

Wichtige Klassen:

```
RequestConfig → speichert Profil
MainWindow → GUI + Logic
perform_site_login() → Login Engine
perform_request() → API Calls
```

---

## 📜 Lizenz

MIT License — frei verwendbar für private und kommerzielle Projekte.

---

## ❤️ Credits

Erstellt mit:

* Python
* QtPy
* requests

---

## 🚀 Roadmap (optional geplant)

* Dark Mode
* History Viewer
* WebSocket Support
* OAuth Login
* Request Replay
* Export to cURL

---

**Viel Spaß beim Debuggen und API testen 🎯**
