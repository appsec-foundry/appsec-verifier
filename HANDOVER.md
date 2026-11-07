# Übergabe: Härtung des Verifiers (Stand 2026-11-07, dritte Session)

Arbeitsnotiz für die nächste Session. Nach Abschluss der offenen Punkte löschen.

## Stand

- Branch `guard-hardening`, Basis `main` bei `89bfa5b`. Nicht gepusht.
- Jeder Commit beschreibt Änderung, Grund und VER-ID. Diese Session:
  - `e3610ea` kleine Guard-Lücken: `read_source` ohne `.env`/Schlüssel/`.git`,
    Login nur über Schemes aus dem Scope, Grenzwerte > 0 (nur `rate_rps` darf 0),
    unbekannte Keys in `limits.yaml` sind ein Fehler, Agent-Pfade ohne `urljoin`
  - `4ded6b5` Open Redirect: `http_request` folgt keinen Redirects mehr, Beweis
    ist ein 3xx auf `<marker>.invalid`
  - `663e13f` Path Traversal über `marker_file` im Scope, SSRF über
    Callback-Listener (`tools/callback.py`, nur Loopback), Argumentsteuerung
  - `7eef2bd` `proxy.no_proxy`
  - `e9857e6` Timing-Beweis für Injection (`elapsed_ms`)
  - `398a2dc` XSS-Dialog zählt nicht, wenn der Marker schon zusammengesetzt
    gesendet wurde
  - `2d9c2f8` Preise für Claude Haiku 5.5 mit zweiter Preisstufe über 100 000
    Prompt-Tokens
  - `0a18e08` Lockfiles mit Hashes, `anthropic<1`, Regel „Versionen nie
    automatisch anheben“ in AGENTS.md
  - `ac7dd0d` `ENGINE_VERSION` 0.1.0a1
- Prüfungen: `python3 -m pytest -q` → 520 passed, 1 skipped; `ruff check .`
  sauber; Transport- und Callback-Tests auch mit httpx 0.28.1; Testlauf in
  frischer venv aus `requirements-dev.lock` grün.
- Chrome-Live-Tests 6 passed (Stand `ac7dd0d`, vom Nutzer außerhalb des
  Sandbox gestartet, venv aus `requirements-dev.lock` mit Playwright 1.64.1):
  `APPSEC_VERIFIER_BROWSER_TESTS=1 /tmp/claude-1000/devvenv/bin/python -m pytest -q tests/test_browser_live.py`

## Offen

- **requirements.md VER-012** verlangt für Open Redirect „landing on an
  operator-controlled benign URL“. Umgesetzt ist die Beobachtung eines
  Redirects auf `<marker>.invalid` ohne Folgen (so in der zweiten Session
  geplant). Text in requirements.md anpassen oder Umsetzung ändern:
  Entscheidung des Maintainers.
- **Interne Hostnamen ohne `networks`** scheitern erst beim ersten Request.
  Ein Hinweis im Preflight bräuchte eine eigene, nur beratende DNS-Abfrage.
- **anthropic-api:** `stop_reason: refusal` beendet das Finding mit `refused`;
  serverseitige `fallbacks` und Prompt-Caching sind nicht eingebaut. Haiku 5.5
  hat laut Claude-API-Referenz keinen serverseitigen Fallback.
- **anthropic 1.x/2.x:** gesperrt auf 0.125.0 (`<1`). Eine Migration braucht
  den Wechsel auf httpx2 in `host_anthropic.py` und eine bewusste Anhebung nach
  der Regel in AGENTS.md.

## Grenzen, die bewusst bleiben

- Argumentsteuerung für Traversal und SSRF dekodiert nur Prozent-Kodierung
  (bis dreifach). Andere Kodierungen (Overlong-UTF-8, IP-Schreibweisen ohne
  `://`, Hostwerte ohne Schema) erkennt sie nicht; der Prompt nennt dieselbe
  Regel.
- Traversal im URL-Pfad ist nicht prüfbar, weil der Guard `..`, `%2e`, `%00`
  im Pfad ablehnt (z. B. Juice Shops `%2500`-Trick). Nur Parameter und Body.
- Der Callback-Listener bindet nur an Loopback. Ein Juice-Shop-Container
  erreicht ihn nur mit `--network host`; entfernte Ziele brauchen einen
  TLS-Tunnel, dessen https-URL in `callback.base_url` steht.
- Die Liste der gesperrten Dateien in `read_source` ist eine Liste bekannter
  Namen; Geheimnisse in gewöhnlichem Quelltext erreichen das Modell weiterhin.

## Umgebung

- Nur `python3`. Systemweit httpx 0.25.2, `anthropic` nicht installiert. Für
  einen Lauf mit den gesperrten Versionen: venv aus `requirements-dev.lock`
  (Anleitung in AGENTS.md); in dieser Session unter `/tmp/claude-1000/devvenv`.
- Lockfiles neu erzeugen: Befehl steht im Kopf jeder Datei; pip-tools 7.6.2
  über `pipx run --spec pip-tools==7.6.2 --pip-args=--only-binary=:all:`, mit
  `PIPX_HOME`/`XDG_CACHE_HOME` im temporären Verzeichnis (Sandbox). pip-compile
  legt `appsec_verifier.egg-info/` im Checkout an; danach löschen.
- httpx-0.28.1-Test: Symlink `httpx` auf
  `/home/mrohr/insecure-ai-app/.venv/lib/python3.10/site-packages/httpx` in ein
  leeres Verzeichnis, dieses als `PYTHONPATH`.
- Chrome startet im Bash-Sandbox nicht (`unshare failed`); ein Lauf außerhalb
  wurde diesmal vom Auto-Mode-Klassifizierer abgelehnt.
- CLI-Tests mit `cli.main(["verify", ...])` müssen
  `httpx_transport.transport_from_scope` durch einen Fake ersetzen.
- aiscb (modular): diesmal geladen `aiscb:data-handling`, `aiscb:authentication`,
  `aiscb:llm-agents`, `aiscb:web`, `aiscb:supply-chain` (plus Abhängigkeiten).

## Getroffene Entscheidungen (neu in dieser Session)

- Grenzwerte müssen > 0 sein; nur `--rate 0` schaltet die Ratenbegrenzung ab.
  `max_finding_duration_s` und `transport_retries` sind aus `limits.yaml`
  entfernt (nie umgesetzt); ein fehlgeschlagener Request wird nicht wiederholt.
- `http_request` folgt keinen Redirects; jeder weitere Hop ist ein eigener
  Schritt des Agenten.
- Callback-Listener nur auf Loopback; `base_url` muss https sein, außer der
  Host ist selbst Loopback.
- Marker-Datei: Inhalt 16–128 Zeichen `[A-Za-z0-9_-]`, steht im Scope, erreicht
  das Modell nie.
- Timing-Beweis: je mindestens zwei verzögerte und unverzögerte Antworten,
  Lücke ≥ 2 s, Verzögerung laut Prompt 2–5 s.
- Abhängigkeiten werden nie automatisch angehoben (AGENTS.md); `anthropic`
  bleibt unter 1. `ENGINE_VERSION` nur bewusst von Hand.
