# Übergabe zur Verbesserung der Evidence Prüfungen


Aktualisierung der Umsetzung: Die folgenden Empfehlungen wurden im Verifier
weiterbearbeitet. Der aktuelle Code enthält strukturierte Prüfplanung mit
Konsolen- und Berichtsausgabe, begrenzte Zusatzauswahl unterhalb der
Schweregradgrenze, aufgelösten Architekturkontext und explizite Abhängigkeiten,
Varianten-Resume mit Proof-Vertrag 3 sowie Zuordnung von Browser- und
Callback-Belegen. Injection verwendet frische Kontrollwerte für SQL, NoSQL,
LDAP und arithmetische Auswertungen für Command-, Template- und XPath-Fälle.
Ein Literal-Eingabevertrag in der Scope-Datei ist Voraussetzung; Timing allein
bestätigt keine Injection mehr. Authentifizierungs-/Expositionsprüfungen nutzen
deklarierte harmlose Ressourcen, Session-Prüfungen deklarierte Sitzungscookies.

Die historischen Reproduktionen und Testzahlen weiter unten beschreiben den
vorherigen Stand. Eine Live-Modell-Evaluation ist weiterhin offen. Die neue
Browser-Zuordnung ist konservativ: Unterframes bleiben unbestätigt. Session-
Fixierung, Logout und Ablaufdurchsetzung benötigen eigene Ablaufnachweise.
Walkthrough-Markdown-Fragmente werden nicht automatisch eingelesen; vorhandene
`attack_steps` und optionaler strukturierter Kontext werden genutzt. Die
aktuellen Bedienhinweise und Scope-Felder stehen in `docs/cli.md`.

Stand: 8. November 2026. Zuerst die Zuverlässigkeit der Beweise verbessern, danach weitere Testfähigkeiten ergänzen. Eine sichere, parametrisierte SQL-Suche kann aktuell als bestätigte Injection gelten. Das ist der erste zu bearbeitende Fehler; mehr Kontext oder zusätzliche Payloads allein beheben ihn nicht.

## Ausgangsstand und Umfang

Die bisherige Umsetzung liegt lokal auf `main` in beiden Repositories:

- Verifier `/home/mrohr/appsec-verifier`: `c565eaa`, `agent: plan context-driven experiments and validate cited evidence`.
- Analyzer `/home/mrohr/appsec-analyzer`: `f4e6c5e3`, `assessment: preserve source-grounded runtime verification context`.

Es wurde nichts gepusht und keine Version geändert. Das bereits vorhandene, unversionierte Verifier-Verzeichnis `verification-2/` wurde nicht angefasst oder committet. Diese Übergabe dokumentiert weitere Empfehlungen; ihre Umsetzung gehört nicht zu den obigen Commits.

Der Analyzer liefert optional `verification_context` Version 1 mit Varianten, Request und Input, belegtem Query- oder Sink-Aufbau, Verarbeitungsreihenfolge, Kontrollen, Voraussetzungen, Beobachtungen, Gegenproben, Quellen und Unsicherheiten. Der Kontext wird validiert und bei Merge und Pentest-Export übernommen. Beide Repositories verwenden dasselbe Schema `schemas/verification-context.schema.json`. Die Analyzer-Anforderung REQ-049 und ihr Wortlaut wurden vom Nutzer genehmigt; die Entscheidung steht in `specs/changes/runtime-verification-context/proposal.md` im Analyzer.

Der Verifier übernimmt diesen Kontext, bietet `read_context`, `plan_test`, begrenztes `read_response` und Formulardaten an. Injection-Beweise benötigen deklarierte, wiederholte Kontrollen; Zugriffskontrollbeweise benötigen vom Betreiber deklarierte Testressourcen und unabhängige Identitäten. Der Code prüft Belege, setzt die Konfidenz und gibt bei unzureichenden Beweisen begrenzt Rückmeldung an den Planner. Berichte zeigen den geprüften Ausschnitt. Scope, Budget, Browser-Isolation und bestehende Freigaben bleiben maßgeblich.

Ältere Assessments bleiben lesbar. Neue strukturierte Informationen entstehen durch eine neue Analyse mit dem aktualisierten Analyzer; ein bloßer erneuter Export erzeugt fehlenden Kontext nicht. Ein neuer Scan ist keine Voraussetzung, um den Verifier selbst weiterzuentwickeln.

## Bestätigte Lücken und nächste Schritte

### 1 Injection von normalem Anwendungsverhalten unterscheiden

**Reproduzierter Fehler.** `injection_check` in [experiments.py](../appsec_verifier/agent/experiments.py) akzeptiert stabile, nichtleere gleiche Ergebnisse für Baseline und positive Eingabe sowie ein abweichendes negatives Ergebnis. Die Prüfung unterscheidet nicht ausreichend, ob die Ursache eine Query-Manipulation oder normale Anwendungslogik ist. Auch eine gültige `plan_test`-Deklaration verhindert das nicht.

Das untenstehende Gegenbeispiel läuft durch `AgentProbe`, Toolvalidierung, Fake-Transport und Beweisprüfung. Die SQL-Abfrage ist parametrisiert. `apple` und `APPLE` finden denselben Datensatz, `banana` keinen. Ergebnis des aktuellen Codes: sechs Requests, `confirmed`, `proof.checked == true`. Der Planner ist vorgegeben; der Versuch belegt die Fehlklassifikation im Prüfer, nicht ihre Häufigkeit bei echten Modellen.

**Nächster Schritt:** Das Beispiel als Regressionstest übernehmen. Anschließend ein mechanismusspezifisches Beweiskonzept festlegen, das normale Suchsemantik, Filterreaktion und Query-Manipulation auseinanderhält. Keine bloße Prüfung auf SQL-Schlüsselwörter ergänzen. Ein Modelltext oder die statische Behauptung des Analyzers darf den Laufzeitbeweis nicht ersetzen. Bei nicht unterscheidbaren Ursachen bleibt das Ergebnis `inconclusive`.

**Abnahme:** Die sichere Vergleichsanwendung wird nicht bestätigt; eine gezielt verwundbare Vergleichsanwendung bleibt mit passenden Gegenproben nachweisbar. Reine Reflexion, gewöhnliche Suchtreffer, Filterfehler und instabile Antworten reichen nicht aus. Timing-Beweise separat gegen normale Rechenlast und schwankende Laufzeiten prüfen; für diese wurde hier kein Gegenbeispiel ausgeführt.

### 2 XSS Ausführung ihrem Sicherheitskontext zuordnen

**Codebefund.** In [browser.py](../appsec_verifier/tools/browser.py) ignoriert die Callback-Funktion von `expose_binding` das Argument `source`. `executed` wird aus dem passenden Markertext abgeleitet. Frame und Origin des Ereignisses sind nicht Teil der Beweisentscheidung. [proof.py](../appsec_verifier/agent/proof.py) verlangt für XSS keinen ausgewählten Variantenplan. Ein konkreter Browser-Fehlalarm wurde in dieser Review nicht ausgeführt.

**Nächster Schritt:** Ereignis, Versuch, Dokument, Frame und effektiven Sicherheitskontext verknüpfen. Ausführung in einem anderen oder isolierten Frame nicht automatisch als Ausführung mit den Rechten der behaupteten Anwendung bewerten. HTML-, Attribut-, JavaScript- und DOM-Kontext für die Testwahl nutzen. CSP-Verletzungen, Skriptfehler und relevante DOM-Beobachtungen nur soweit erfassen, wie sie die nächste Entscheidung erklären.

**Abnahme:** Tests unterscheiden korrekte Ausführung, fremden oder isolierten Frame, bloße Reflexion und ein Ereignis aus einem anderen Versuch. Browserzugriffe bleiben vollständig kontrolliert. Begrenzte Klick-/Formularaktionen und Stored-XSS-Abläufe erst hinzufügen, wenn konkrete Findings sie benötigen; Schreib- und Leserolle sowie Zustandsänderungen ausdrücklich abbilden.

### 3 Varianten getrennt abschließen und fortsetzen

**Bestätigte Verwaltungslücke.** `verified_findings` in [report.py](../appsec_verifier/verify/report.py) liefert Finding-IDs zurück, sobald ein definitives Ergebnis mit geprüftem Proof-Vertrag 2 existiert. [cli.py](../appsec_verifier/cli.py) verwendet diese Menge für Resume. Ein geprüftes Ergebnis für Variante 1 kann damit das gesamte Finding überspringen. `merge_reports` ersetzt ebenfalls auf Finding-Ebene. Die Berichtsausgabe weist bereits darauf hin, dass andere Varianten ungetestet bleiben; das löst die Resume-Lücke nicht.

**Nächster Schritt:** Ergebnis, Zusammenführung und Resume auf Finding und Variante beziehen. Stabile Variantenidentität über neue Assessments berücksichtigen: Der Analyzer vergibt beim Merge derzeit fortlaufende IDs. Bei geänderter Quelle, Route, Identität oder Testvoraussetzung keine unpassenden früheren Ergebnisse übernehmen. Alte Berichte kompatibel und ohne erfundene Variantenabdeckung behandeln.

**Abnahme:** Von zwei Varianten wird beim Fortsetzen nur die tatsächlich erledigte übersprungen. Ein negatives Ergebnis einer Route gilt nicht für eine andere. Zusammenfassungen und Annotationen unterscheiden bestätigte Schwäche und verbleibende Testabdeckung.

### 4 Vorprüfung und begründete Anpassung vervollständigen

**Teilweise vorhanden.** [prompts.py](../appsec_verifier/agent/prompts.py) fordert Kontextauswertung, Hypothese und Anpassung an Filter. [tools.py](../appsec_verifier/agent/tools.py) prüft Planstruktur, Route, Eingabe und verfügbare Fähigkeiten. [loop.py](../appsec_verifier/agent/loop.py) unterstützt begrenztes `proof_feedback`. Diese Teile wiederverwenden. Es gibt keine erzwungene fachliche Vorprüfung und keine belastbare Auswahl des besten Ansatzes.

**Nächster Schritt:** Vor Beweisversuchen Mechanismus, Laufzeitvoraussetzungen, relevante Unbekannte, erwartete Beobachtung, Gegenhypothese und Abbruchkriterium festhalten. Ungefährliche Diagnose- und Baseline-Anfragen müssen vorher möglich bleiben. Nach einem Fehlschlag zwischen fehlendem Login, falscher Route, Filterreaktion, nicht erreichtem Sink, fehlender Fähigkeit und unzureichendem Beleg unterscheiden. Nur eine begründete nächste Änderung vornehmen; keine allgemeine Payload-Liste abarbeiten.

**Abnahme:** Fehlender Kontext führt zu einer gezielten Nachfrage an die vorhandenen Werkzeuge oder einem begründeten offenen Ergebnis. Wiederholte identische Fehlversuche verbrauchen nicht das gesamte Budget. Eine zusätzliche Analyzer-Runde oder ein separater Planungsagent ist zunächst nicht erforderlich.

### 5 SSRF korrelieren und weitere Klassen nach Bedarf ergänzen

**Codebefund SSRF.** [callback.py](../appsec_verifier/tools/callback.py), `http_request` in [tools.py](../appsec_verifier/agent/tools.py) und `_ssrf` in [proof.py](../appsec_verifier/agent/proof.py) verwenden den Marker des Findings. Bereits eingegangene Treffer können spätere Versuche begleiten. Die Zuordnung ist nicht pro Versuch. Ein Callback belegt einen Abruf, aber nicht automatisch jede behauptete unerlaubte interne Erreichbarkeit.

**Nächster Schritt SSRF:** Marker pro Versuch, explizite Zuordnung verspäteter Treffer und begrenztes Beobachtungsfenster. Erlaubte Fetch-Funktion und konkret behauptete Grenzverletzung unterscheiden. Kein Treffer bedeutet nicht automatisch sichere Anwendung. Die bestehende Beschränkung auf den kontrollierten Listener bleibt erhalten.

**Management-Endpunkte:** Erreichbarkeit, Authentifizierung, Autorisierung und tatsächlich zugängliche Funktion getrennt bewerten. Eine öffentliche Health-Antwort ist nicht automatisch eine Schwachstelle; eine Login-Seite kein Nachweis eines Datenlecks. Betreiberressourcen und harmlose Beobachtungen verwenden. Keine Heapdumps, Secrets oder verändernden Verwaltungsaktionen zur Beweisführung benötigen. Fehlende Autorisierung kann teilweise in die bestehende Zugriffskontrollklasse passen; nicht pauschal eine neue Klasse schaffen.

**XXE:** Der aktuelle [CWE-Katalog](../data/verifiable-cwes.yaml) enthält keine eigene XXE-Klasse. Zunächst XML-Eingabepfad, Parseroptionen und beobachtbare Wirkung klären. Falls konkrete Findings dies erfordern, begrenzte XML-Requests und Beweise über harmlose Marker oder kontrollierte Callbacks ergänzen. Fehlende Toolfähigkeit darf nicht als widerlegter Befund erscheinen.

Command-, Template-, LDAP- und XPath-Injection erst anhand konkreter Findings und eigener Beweiskriterien priorisieren. Vor Erweiterungen die vorhandenen Klassen verlässlich machen.

### 6 Tatsächliche Testauswahl mit Modellen evaluieren

**Nachweisgrenze.** `test_filter_order_drives_a_repeatable_query_experiment` in [test_context_runtime.py](../tests/test_context_runtime.py) gibt dem Planner die passende Umgehung bereits vor. Das prüft den Ablauf, nicht die selbstständige Entdeckung. Es gab keine Live-Modell-Evaluation.

**Nächster Schritt:** Verwundbare und sichere Vergleichsfälle mit unterschiedlicher Filterreihenfolge, Binding, XSS-Kontexten und fehlenden Voraussetzungen bereitstellen. Legacy-Kontext und strukturierten Kontext unter vergleichbarem Budget auswerten. Fehlalarme, übersehene Befunde, passende Testwahl, offene Ergebnisse sowie Requests, Modellaufrufe und Kosten getrennt messen. Deterministische Regressionstests bleiben Teil der Offline-Suite; Modell-Evaluationen separat und nur mit autorisiertem Budget ausführen.

## Analyzer Kontext gezielt ergänzen

Die Richtlinien `data/stride-analysis-policy.md`, `data/test-case-investigation-policy.md` und `data/open-review-policy.md` im Analyzer verlangen bereits Quellen, Query-/Sink-Ausdrücke, Verarbeitungsreihenfolge, Kontrollen und Unsicherheiten. Zunächst prüfen, ob diese Informationen im konkreten Assessment fehlen, vom Modell nicht geliefert oder vom Verifier nicht genutzt werden.

Zusätzliche strukturierte Angaben, etwa XSS-Ausgabekontext oder XML-Parseroptionen, erst aus einer belegten Lücke ableiten. Keine unbekannte Filterumgehung als Tatsache ausgeben. Neue Quellenangaben müssen durch die bestehenden Source-Admission-Prüfungen laufen. Änderungen am gemeinsamen Schema in beiden Repositories und an den direkten Exportverbrauchern prüfen.

## Reproduktion der Injection Fehlklassifikation

Im Verifier-Checkout ausführen. Der Versuch verwendet ausschließlich SQLite im Speicher und den vorhandenen Fake-Transport, keine Zielanwendung oder Modell-API. Er verändert keine Repository-Dateien.

```sh
PYTHONPATH=tests:. python3 - <<'PY'
import json
import sqlite3
import tempfile
from dataclasses import replace
from pathlib import Path

from test_agent_tools import Resp, _ctx
from test_experiments import plan
from appsec_verifier.agent.loop import AgentProbe

db = sqlite3.connect(':memory:')
db.execute('CREATE TABLE products (id INTEGER, name TEXT)')
db.execute('INSERT INTO products VALUES (?, ?)', (7, 'apple'))
seen = []

def target(method, url, headers, **kwargs):
    value = kwargs['params']['q']
    seen.append(value)
    rows = db.execute(
        'SELECT id FROM products WHERE lower(name) = lower(?)', (value,)
    ).fetchall()
    return Resp(200, json.dumps({'result': [row[0] for row in rows]}))

declaration = plan(baseline='apple', positive='APPLE', negative='banana')['args']
actions = [{'tool': 'plan_test', 'args': declaration}]
actions += [
    {'tool': 'http_request', 'args': {
        'path': '/search', 'params': {'q': declaration[group]}
    }}
    for _ in range(2)
    for group in ('baseline', 'positive', 'negative')
]
actions.append({'verdict': {
    'verdict': 'confirmed', 'rationale': 'Repeated result difference',
    'proof_steps': list(range(2, 8))
}})

class Planner:
    def next_step(self, context, history):
        return actions.pop(0)

with tempfile.TemporaryDirectory(prefix='verifier-review-') as tmp:
    ctx = _ctx(Path(tmp), target)
    ctx.plan = replace(ctx.plan, cls='injection')
    result = AgentProbe('injection', Planner).run(ctx)
    print(json.dumps({
        'requests': len(seen), 'verdict': result.verdict,
        'proof_checked': result.proof.get('checked')
    }, indent=2))
db.close()
PY
```

## Bisherige Validierung

- Verifier: vollständige Offline-Suite `921 passed, 1 skipped`; spätere gezielte Review `python3 -m pytest -q tests/test_experiments.py tests/test_context_runtime.py` mit `39 passed`. `ruff check .` vor dem Commit sauber. Die grüne Suite deckt die oben reproduzierte Fehlklassifikation bisher nicht ab.
- Analyzer: fokussierte Gruppen mit 379, 336 und 87 erfolgreichen Tests. `make check-analyzer BASE=HEAD` lief einmal vor dem Commit: 1112 öffentliche Tests erfolgreich; die weitere Gruppe hatte 167 erfolgreiche Tests und einen Fehler wegen der alten Erwartung „48 requirements“. Die Erwartung wurde auf 49 korrigiert und der betroffene Test anschließend einzeln erfolgreich ausgeführt. Das gesamte Gate wurde danach nicht erneut ausgeführt und wird daher nicht als vollständig grüner Lauf bezeichnet.
- Analyzer: Ruff und Formatprüfung der sieben geänderten Python-Dateien vor dem Commit erfolgreich. Beide Kontextschemas identisch; Diff-Prüfungen sauber. Analyzer-Export und Verifier-Import wurden zuvor mit einer lokalen Fixture zusammen geprüft.
- Keine Live-Analyse, Live-Modell-Evaluation oder erneute Browser-Live-Prüfung. Frühere Testlogs liegen temporär unter `/tmp/verifier-context-change/`; sie können in einer neuen Session fehlen. Ältere Fehlerlogs in diesem Verzeichnis beschreiben teilweise bereits korrigierte Zwischenstände.

## Einstieg für die nächste Session

Empfohlene Reihenfolge: Injection-Regression und Beweiskonzept, XSS-Zuordnung, Variantenverwaltung. Begleitend die Vergleichsfälle für Evaluation vorbereiten; danach Planung und SSRF vertiefen. Management und XXE nach tatsächlich benötigter Abdeckung ergänzen.

Möglicher Startauftrag:

> Lies `docs/internal/analysis/evidence-verification-handoff-2026-11-08.md` und die geltenden AGENTS.md. Beginne mit Punkt 1: Reproduziere die Fehlklassifikation, ergänze einen Regressionstest und verbessere das Beweiskonzept so, dass normale parametrisierte Suchlogik nicht als Injection bestätigt wird. Behalte einen verwundbaren Vergleichsfall bei. Bearbeite zunächst nur diese Lücke und erläutere verbleibende Nachweisgrenzen.

Vor der Arbeit den aktuellen Git-Stand prüfen. Die bisherigen Commits liegen auf `main`; die Übergabe ersetzt keine aktuelle Branch- oder Ausführungsentscheidung. Für neue Analyzer-Features gelten dessen Anforderungen an genehmigten Anforderungswortlaut und Branchwahl; Bugfixes innerhalb bestehender Zusagen separat einordnen. Keine weiteren Modellkosten, Zielsystemtests, Releases oder Pushes aus diesem Dokument ableiten. Scope, Identitäten, Budgets und bestehende Freigaben der Testwerkzeuge nicht lockern.
