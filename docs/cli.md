# AppSec Verifier: command guide

This guide explains how to run the Verifier: the commands, the options you are likely to need, the scope and identities files, and what a run produces. Installation and a first run against OWASP Juice Shop are in the [README](../README.md), and [How verification works](how-verification-works.md) explains how a verdict comes about. Every rule in full, rarely used options and edge cases included, is in the [specification](specification.md).

## Commands

| Command | What it does | What it contacts |
| --- | --- | --- |
| `appsec-verifier ASSESSMENT` | Guided run: asks for the settings it cannot work out itself, then runs `verify`. | target, model |
| `verify` | Tests the selected findings against the running application and writes a report. | target, model |
| `preflight` | Checks the files, the target, the logins and the model, and shows which findings a run can test. Tests no finding. | target, model provider; nothing with `--offline` |
| `scope` | Checks a scope file and shows what lies inside it. | nothing |
| `export` | Converts the results into a file for AppSec Analyzer. | nothing |
| `runs` | Lists earlier runs and removes the ones you choose. | nothing |
| `update` | Updates a pipx installation of the Verifier. | the install source |

`appsec-verifier --help` lists the commands, and `appsec-verifier <command> --help` lists the options of one command with examples. Write options in full: an abbreviation such as `--show-cost` is an error that suggests the right option.

## Guided run

```sh
appsec-verifier ./appsec-assessment.yaml
```

The guided run reads the assessment, shows how many of its findings can be tested against a running application, and asks only for what it cannot work out itself: the target URL, an identities file when it finds one, whether write requests are allowed when the scope file permits them, and whether to replace a report already in the `--output` directory. A `scope.yaml` next to the assessment or in the working directory is used without a question, and the run then does not ask for the URL.

By default the run tests findings of severity high and above with the `claude` profile. If there are none, it offers the next lower severity. Every `verify` option works here too and skips its question, so `appsec-verifier ./appsec-assessment.yaml --url http://localhost:3000` asks only for the confirmation.

When access-control findings need test accounts and there is no identities file, the run offers to take a session from your browser. Sign in to the application, open the developer tools, copy any request to the application in the Network tab with "Copy as cURL (bash)" and paste it at the prompt. The Verifier keeps only its cookie and authorization headers. A pasted session is not renewed, so the account's tests end when it expires.

Before it starts, the run shows its settings and the matching `verify` command, which you can reuse for a run without questions. Enter starts the run. Ctrl-C at any question stops it before anything is contacted.

## Verify findings

```sh
appsec-verifier verify --assessment ./appsec-assessment.yaml --scope ./scope.yaml \
  --identities ./identities.yaml --min-severity high --cost-limit 5 --output ./verification
```

Before it sends anything, `verify` checks the assessment, the scope, the identities and the model profile, and shows the test plan: the findings it will test, in order, with the requests the assessment names for each. Under `Not testable` it lists the findings this run cannot test and what they need, such as a second test account, `--allow-intrusive` or a marker file. These findings are reported as `not-attempted`; `--test-all` tests them anyway. `--dry-run` shows the plan and stops without contacting anything.

After you confirm, the Verifier checks that the target answers, that every test account can sign in and that the model responds. Then it tests the findings, up to four at the same time, and writes the report.

### Target and scope

`--url` names the target. Without a scope file the Verifier contacts only that URL's scheme, host and port, and sends only reading requests. A [scope file](#scope-file) given with `--scope` can allow more, such as several hosts, a private network or a proxy, and records the test period and who is responsible. With a scope file `--url` is optional and must lie inside the scope.

`--source DIR` lets the test agent read a checkout of the application's source code. The agent uses it to find the exact request of a finding when the assessment does not name it. It never reads `.env` files, keys, credential stores or `.git/`.

### Test accounts

Many findings need signed-in accounts, and an access-control finding usually needs two. Use accounts made for the test, because the Verifier acts with their rights.

- `--account USER` names an account by its user name. Repeat it for a second account. Two accounts let the Verifier show without `--allow-intrusive` that one reads the other's record where the record names its account's user name, such as a user profile, or where the list of its collection, such as `GET /api/orders` for `/api/orders/:id`, shows each account only its own records; the second way also works with accounts from an identities file. See [Test accounts on the command line](#test-accounts-on-the-command-line).
- `--admin-account USER` names a privileged account. It only reads, also with `--allow-intrusive`.
- `--identities FILE` takes the accounts from an [identities file](#identities-file), which covers every other kind of login.

The model never sees a password. It knows the accounts only by role names such as `account-1`.

### Choosing findings

Without a selection, `verify` tests every finding that can be tested against a running application.

| Option | Selects |
| --- | --- |
| `--category LIST` | classes or techniques, e.g. `xss,idor,sqli`; `quick` selects XSS and SQL or NoSQL injection findings with a reading request, which are cheap to confirm |
| `--severity LIST` | exact severities, e.g. `critical,high` |
| `--min-severity LEVEL` | a severity and everything above it: `low`, `medium`, `high` or `critical` |
| `--only IDS` | specific findings, e.g. `T-003,T-009`; ignores the other options |

Options combine, so `--category xss --min-severity high` tests the XSS findings of severity high and critical. `--cwe` and `--class` select by CWE or weakness class.

The run tests the `quick` findings first, then the others, most severe first. A finding the assessment describes with several variants, that is several requests for the same weakness, stops once one variant confirms it.

### Model and costs

`--profile` chooses the model that plans the tests: `claude` (the default), `codex-cli`, `copilot-cli`, `codex` or `anthropic-api`. The [README](../README.md#model-profiles) lists what each one needs. `--model` chooses another model of the same profile. If a profile cannot be used, for example because its CLI is not logged in, the run stops before it contacts anything. If the model refuses to answer, the console and the report say so and the finding ends `inconclusive`; another model or a new run may get further.

With API billing the console shows what the run has cost so far. With a Claude subscription `--show-costs` shows what the calls would cost at API prices. `codex-cli` and `copilot-cli` report no costs.

`--cost-limit USD` caps the model costs of the run; the default is USD 10. When a run in a terminal reaches the limit, it asks for a higher one: type the new total, such as `20`, or press Enter to stop. Without a terminal the run stops at the limit. One finding may use a quarter of the limit, but never less than USD 0.50, so a single difficult finding cannot use up the whole run.

### Limits

Every run has limits on model costs, model calls, requests to the target, steps per finding, run time and request rate. The defaults are in [`data/limits.yaml`](../data/limits.yaml), and these options change them for one run:

| Option | Limits | Default |
| --- | --- | --- |
| `--cost-limit USD` | model costs; not with `codex-cli` and `copilot-cli` | 10 |
| `--max-calls N` | model calls | 500 |
| `--max-requests N` | requests to the target | 2000 |
| `--max-attempts N` | agent steps per finding | 12 |
| `--max-duration SECONDS` | run time | 1800 |
| `--rate N` | requests per second; `0` turns the limit off | 5 |
| `--parallel N` | findings tested at the same time, 1 to 8 | 4, or 2 with `codex-cli` and `copilot-cli` |

The limits apply to the whole run, also when it tests several findings at the same time, so `--parallel` raises neither the load on the target nor the costs. Lower it if your model provider limits how many requests you may send.

A finding that runs out of steps ends `inconclusive`, and the run goes on. When a limit of the whole run is reached, the findings under test end `inconclusive`, the remaining ones `not-attempted`, and the run writes its report and exits with code 3.

### Write requests

By default the Verifier sends only GET, HEAD and OPTIONS. Some findings, such as stored XSS or a change to another account's record, can only be shown with a write. `--allow-intrusive` allows POST, PUT and PATCH. DELETE is never sent. Each write carries a marker of its finding, and the Verifier refuses a write that would change an existing record.

What a write creates stays on the target. Use intrusive mode only on a test instance you can reset, and check the target before you confirm: a `localhost` reached through `ssh -L` or `kubectl port-forward` is a remote system.

Without `--allow-intrusive`, the test agent can ask you during the run for a write it did not foresee. `y` allows writes for that finding and `a` for the rest of the run. Enter, any other answer or two minutes without an answer decline. `--read-only` forbids writes and turns the question off, and so does `allow_state_change: false` in the scope file.

### Runs without questions

For CI and scripts, `--non-interactive` (or `--ci`) turns all questions off, as does running without a terminal. `--profile` is then required, `--yes` gives the confirmation, and every environment variable the identities file names must be set. Sign-ins that need a person, in the browser or with a device code, are not possible; use a login program or client credentials instead. Run `preflight` with the same options first to check the files.

### Output directory and resuming

Without `--output`, every run writes to a new directory that only you can read, on Linux `~/.local/share/appsec-verifier/runs/<project>/<start time>/`, on macOS under `~/Library/Application Support` and on Windows under `%LOCALAPPDATA%`. [`runs`](#runs) lists and removes these directories. `--output DIR` writes into a directory you choose. If it already holds a report, the run stops unless you add `--overwrite` or `--resume`.

`--resume` continues an interrupted or limited run. Findings that were confirmed, shown without exploit, not reproducible or blocked by a control keep their verdict, and the others are tested again. Without `--output` it continues the newest run for the same assessment and target.

Ctrl-C stops a run. The finding under test ends `inconclusive`, and the report is still written.

## What the results mean

Each tested finding gets one verdict. A negative verdict applies only to the requests that were tested.

| Verdict | Meaning |
| --- | --- |
| `confirmed` | The weakness was reproduced, and the Verifier's code checked the proof. |
| `shown-without-exploit` | The target showed the weakness without an exploit, and the Verifier's code checked that proof. It is not a confirmation and does not change the rating. |
| `not-reproducible` | Tested, but the weakness did not show. |
| `blocked-by-control` | A protection the static analysis could not see stopped the attack. |
| `inconclusive` | No decision, for example because a request failed, a limit was reached or the proof did not hold. |
| `not-attempted` | Not tested: the finding cannot be tested against a running application, the run lacked something it needs, or a limit or Ctrl-C ended the run first. |

What counts as proof depends on the weakness. An XSS counts only when a marker script actually runs in the proof browser. An access-control finding needs a comparison in which another account, or a request without login, gets what it must not. An injection needs answers that follow true and false conditions the Verifier generates, or a database error that only the broken input causes. Code that is evaluated but returns no result can be shown without exploit: names no code can know make it fail, names the language always knows do not. The README's table [What it verifies](../README.md#what-it-verifies) lists every class, and the [specification](specification.md#proof-per-class-ver-009-to-ver-013) has the exact rules.

For access control the Verifier assumes the usual restrictions unless you declare others: a request without login must not get an account's data, one account must not read or change a record another account created, one that names that account or one that only that account's list shows, and a normal account must not get an admin's answer. The report says when a restriction was assumed. If some data is public on purpose, say so in the scope file's [`access_rules`](#scope-file), or run with `--declared-access-only` to rely on declared rules alone.

The report shows a rating after verification next to the Analyzer's. A confirmed finding whose likelihood was below High gets likelihood High and a severity one level higher, and a finding blocked by a control is one level lower in both. Otherwise the rating stays as it was.

### Console output

While it runs, `verify` prints one line per event, in the columns time, finding, event, progress, elapsed time, estimated time left and details.

| Event | Shows |
| --- | --- |
| `start` | a finding begins: title, severity and requests |
| `agent` | the test agent starts or finishes, with its model and step limit |
| `·` | one step: what the agent does and, below it, the request or source file and the result |
| `↻` | a step the Verifier refused |
| `⚠` | a limit or repeated failed actions stopped the finding |
| `proof` | the result of the proof check |
| `rating` | the rating after verification differs from the Analyzer's |
| `done` | the verdict, the time the finding took and, for a confirmed finding, a short explanation |

At the end, `Results` lists each finding with its verdict and the reason. For a finding the run could not test, it says what is missing and how to add it. `Done` names the files the run wrote.

The output is in colour on a terminal. `NO_COLOR` turns colour off, and `FORCE_COLOR=1` turns it on without a terminal. `--console-log` also saves the output as `console.log`.

| Exit code | Meaning |
| --- | --- |
| `0` | All selected findings were tested, whatever the verdicts. |
| `2` | The run did not start, for example because of an invalid file, an unreachable target, a failed login or a missing confirmation. The error message says what to do. |
| `3` | A limit was reached, such as the cost limit or the end of the test period. |
| `130` | Stopped with Ctrl-C. |

### Files a run writes

| File | Content |
| --- | --- |
| `verification.md` | The report: a summary table, then per finding the verdict, what the proof showed or why the finding is not confirmed, the requests and a proof of concept. |
| `verification.yaml` | The same results as data, read by `--resume` and `export`. |
| `agent-log.jsonl` | Every step of the test agent, refused steps included, without response bodies. |
| `evidence/` | Per finding the recorded requests and responses as an HTTP archive (`<finding>-poc.har`) that Burp, ZAP or a browser's developer tools can import, and the screenshots and evidence images. |
| `failed-findings.json` | Only when a finding's test failed because of an error: its model calls and the error, to find the cause. |
| `console.log` | With `--console-log`: what the run printed. |
| `appsec-assessment.annotated.yaml` and `.md` | With `--annotate`: copies of the assessment and of the Analyzer's report with the results added to each tested finding. The originals stay unchanged. |

Only you can read these files. Passwords and tokens are masked, but recorded responses and screenshots can show data of the tested application, and `failed-findings.json` contains what the model received. Check them before you share them. `--screenshots` limits screenshots to the classes you name, or turns them off with `none`; the proof does not depend on them.

## Scope file

The scope file says what the Verifier may contact, during which period, and who is responsible. A minimal one:

```yaml
schema_version: 1
base_url: https://staging.example.com
window: {from: "2026-11-01T00:00:00Z", until: "2026-11-30T23:59:59Z"}
owner: {name: Your Name}
```

The Verifier refuses every request outside the scope, and once the window has closed it sends nothing more. Cloud metadata addresses are never contacted. Private and loopback addresses are contacted only when `networks` lists them, or when the host is written as such an address or as `localhost`.

| Key | Purpose |
| --- | --- |
| `hosts`, `ports`, `schemes`, `path_prefixes` | What may be contacted. By default the host, port and scheme of `base_url`. |
| `deny_paths` | Paths that are never contacted. |
| `networks` | Private address ranges a host name may resolve to, e.g. `10.0.0.0/8`. |
| `allow_state_change` | `false` forbids write requests, also with `--allow-intrusive`. |
| `auth_hosts` | Login and token endpoints of an identity provider. They are used only to sign in. |
| `proxy` | A proxy for all requests. Its credentials are named as environment variables. |
| `access_rules` | Who may use a request: `owner`, `signed-in`, `admin` or `anyone`. |
| `test_resources` | A prepared record for an access-control test, with the roles that may and may not read it. |
| `injection_inputs` | The input of an injection finding that must treat its value as plain data. |
| `marker_file` | A file on the target whose content proves a path traversal. |
| `callback` | The listener for SSRF tests, needed when the target is not on `localhost`. |
| `session_checks` | The request that sets a session cookie, for findings about cookie attributes. |

An access rule names a request and who may use it. `:id` stands for any record, so one rule covers them all:

```yaml
access_rules:
  - {request: "GET /api/Users", may: admin}
  - {request: "GET /api/Recycles/:id", may: owner}
```

A finding is then confirmed only when the access the test shows breaks the rule, and a request that `anyone` may use is not tested. The specification describes every key with examples, including the rarely needed `access_policies`, `auth_checks` and `archive_checks` ([scope file](specification.md#scope-file--scopeyaml-authorisation-ver-001)).

If the target or a login host uses a certificate from your own CA, set `SSL_CERT_FILE` to a bundle that contains that CA. It replaces the default bundle, so it must also contain the public CAs of every public host the run contacts.

## Identities file

The identities file lists the test accounts by role name and says how each one signs in. It holds no passwords or tokens, only the names of the environment variables that contain them. Examples are in [`examples/juice-shop/`](../examples/juice-shop/) (form login), [`examples/sso-proxy/`](../examples/sso-proxy/) (sign-in in the browser, behind a proxy) and [`examples/login-program/`](../examples/login-program/) (a login program).

| `method` | How the account signs in |
| --- | --- |
| `form` | an HTML login form, or a JSON login that returns a token, at `login_url` |
| `bearer` | a token from the variable `token_env` |
| `basic` | HTTP Basic with `username_env` and `password_env` |
| `session` | headers copied from a signed-in browser, such as a cookie or an API key |
| `oidc-authorization-code` | you sign in in your browser, MFA included; needs a terminal |
| `oidc-device-code` | you sign in on any device with a code the Verifier shows; also works over SSH |
| `oidc-password` | the OIDC password grant, for test realms |
| `oidc-client-credentials` | client credentials, for service accounts |
| `command` | your own login program prints the session |
| `none` | no credentials, for requests without login |

```yaml
identities:
  - role: customer-a                    # login form or JSON login
    method: form
    auth:
      login_url: http://localhost:3000/rest/user/login
      username_field: email
      username_env: VERIFIER_CUST_A_USER
      password_env: VERIFIER_CUST_A_PASS
  - role: user-b                        # sign-in in your browser
    method: oidc-authorization-code
    auth:
      issuer: https://sso.example.com/realms/app
      client_id: verifier-cli
      scope: openid
      check_url: https://app.example.com/api/me
  - role: user-c                        # your own login program
    method: command
    auth:
      command: [./login.py, user-c]
  - role: anonymous
    method: none
```

Before the run the Verifier checks that every variable the file names is set. In a terminal it asks for a missing value without showing it and keeps it only for that run. To keep a password out of your shell history, set it with `read -rs VERIFIER_CUST_A_PASS && export VERIFIER_CUST_A_PASS`. A secret manager can set the variables for a single command, for example `op run --env-file=verifier.env -- appsec-verifier verify …`.

After the confirmation each account signs in once, and a failed login stops the run. A `bearer`, `basic` or `session` account is checked against the target only when it names a `check_url`. Sessions with a known expiry are renewed shortly before they expire. Copied sessions cannot be renewed.

For the OIDC methods the `issuer` is usually enough, because the Verifier reads the other endpoints from the provider's discovery document. Every endpoint must be the target or an `auth_hosts` entry of the scope. A browser sign-in needs a client at your identity provider that allows a redirect to `http://127.0.0.1` and issues tokens the application's API accepts. An application that keeps its own session cookie after the SSO sign-in needs `session` or a login program instead.

A login program covers every other case, such as a login in several steps. The Verifier runs it without a shell from the directory of the identities file. It prints either one line with a bearer token or a JSON object such as `{"headers": {"Authorization": "Bearer …"}, "cookies": {"SESSION": "…"}, "expires_at": "2026-11-08T14:30:00Z"}`. The program runs with your rights and outside the scope and limits of the run, like a command you start yourself, so the run shows it before you confirm.

Passwords and tokens are sent only to the login endpoint an account names and never appear in logs, reports or model prompts. User names are not secret and appear in the report.

## Test accounts on the command line

For a login that `form` can handle, you can name the accounts on the command line instead of writing an identities file:

```sh
appsec-verifier ./appsec-assessment.yaml --target http://localhost:3000 \
  --account jim@juice-sh.op --account bender@juice-sh.op=VERIFIER_BENDER_PASS --admin-account admin@juice-sh.op
```

`=VARIABLE` names the environment variable that holds the password. Without it the password is asked for and not shown. The accounts sign in at `--login-url`, or else at the login the assessment names, or else at the login form the target URL leads to; the run settings show which before you confirm. The model knows the accounts as `account-1`, `account-2` and `admin-1`.

`--account` cannot be combined with `--identities`. The same user name given twice stops the run, because an access-control proof needs independent accounts. User names stay visible in the report and in your shell history.

## Other commands

### `preflight`

```sh
appsec-verifier preflight --assessment ./appsec-assessment.yaml --scope ./scope.yaml --identities ./identities.yaml
```

Runs the checks `verify` runs before its first finding and tests no finding. Each check prints one line: `✓` passed, `⚠` works with a caveat, `✗` failed, `·` not checked. Then follows the test plan, with what each untestable finding needs and the lines to copy into a scope file. The target and the logins are contacted only after you confirm or with `--yes`. `--offline` contacts nothing. `--test-model` also sends one fixed prompt to the model and needs its own limit, `--cost-limit` or, for `codex-cli` and `copilot-cli`, `--max-calls 1`. `--json` prints the result for scripts. The exit code is 0 when no check failed and 2 otherwise.

### `scope`

```sh
appsec-verifier scope --scope ./scope.yaml --target https://staging.example.com/app
```

Checks the scope file and shows what lies inside it: hosts, ports, paths, test period and owner. With `--target` it also says whether that URL is inside. Contacts nothing.

### `export`

```sh
appsec-verifier export --verification ./verification/verification.yaml --output ./analyzer-verification.json
```

Converts the verdicts of a finished run into a file meant for AppSec Analyzer, keyed by finding. The Analyzer does not read this file. `export` changes nothing in the assessment and contacts nothing.

### `runs`

```sh
appsec-verifier runs
appsec-verifier runs --remove dvwa/2026-11-13T14-30-05
appsec-verifier runs --remove-older-than 30
```

Without options, `runs` lists the runs written without `--output`, newest first, with their state, target and verdicts. `--remove` removes the runs you name as the list shows them, and `--remove-older-than DAYS` the runs that wrote nothing for that many days. Both ask before they remove anything, and removed runs cannot be restored. A run in progress is never removed.

### `update`

```sh
appsec-verifier update
```

Reinstalls the Verifier with pipx from the source you installed it from, after you confirm. Like a fresh `pipx install`, it takes the newest dependency versions allowed, not the pinned ones of `requirements.lock`. An installation without pipx is not changed; update it the way you installed it. `appsec-verifier --version` shows the installed version with its commit and date.
