# Run the Verifier in a container

The container image runs a single `appsec-verifier` command and exits. It opens no network port and contains no credentials; you pass them in when you start the container.

## What the image contains

The image holds the Verifier from the checkout you build it from, Python 3.12 with the pinned packages of [`requirements.lock`](../requirements.lock), and Claude CLI 2.1.311. The profiles `claude`, `anthropic-api` and `codex` work with their API keys.

Not in the image:

- The proof browser. Chrome needs a network namespace of its own, which a container with default restrictions cannot create. In the container XSS findings cannot be confirmed and no screenshots are taken; the other classes do not need the browser. To confirm XSS findings, run the Verifier from an [installation](../README.md#install) outside a container.
- Codex CLI and Copilot CLI, so the `codex-cli` and `copilot-cli` profiles do not work.
- Your Claude login. A `claude auth login` on your machine does not carry over into the container; use `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`.
- The `update` command. To update, build the image again from an updated checkout.

## Build the image

In the Verifier checkout, run:

```sh
docker build -t appsec-verifier .
```

With Podman, replace `docker` with `podman`; the examples below use Docker. The build needs network access to Docker Hub, Debian, PyPI and the npm registry, and it checks every download against the versions and hashes pinned in the [Dockerfile](../Dockerfile) and in [container/requirements.txt](../container/requirements.txt). The image runs on `amd64` and `arm64`.

The image takes only the files Git tracks, uncommitted changes to them included; `--version` then shows `+local changes`. Untracked and ignored files, such as results in `verification/`, stay out. Build in a normal checkout or clone: in a git worktree the build stops, because the worktree keeps its Git data outside the build directory.

## Run with Docker

Mount the assessment, the scope file and the identities file read-only, and a result directory writable. The user in the container must be able to write to the result directory, and which user that is depends on how Docker runs:

- Docker as a system service: your own user ID with group 0, `--user "$(id -u):0"`.
- Rootless Docker, where `docker info` lists `rootless` under security options: `--user 0:0`. Root in the container is then your own user and has no additional rights on your machine.

This line picks the right value for either case:

```sh
if docker info --format '{{.SecurityOptions}}' | grep -q rootless; then user=0:0; else user="$(id -u):0"; fi
```

This example tests the High and Critical findings of an assessment against a target on another machine, with the `claude` profile and a cost limit of USD 5:

```sh
mkdir -p "$HOME/verifications"
docker run --rm --name appsec-verification \
  --user "$user" --cap-drop ALL --security-opt no-new-privileges \
  --env ANTHROPIC_API_KEY --env USER_A_PASSWORD --env USER_B_PASSWORD \
  --volume /path/to/input:/input:ro \
  --volume "$HOME/verifications":/output \
  appsec-verifier verify --non-interactive --yes --profile claude \
  --assessment /input/appsec-assessment.yaml \
  --scope /input/scope.yaml --identities /input/identities.yaml \
  --min-severity high --cost-limit 5 --output /output/project
```

Replace `/path/to/input` with the directory that holds the three files. The report ends up in `$HOME/verifications/project`. Always pass `--output` with a mounted directory: without it the Verifier writes inside the container, and the results are lost when it exits.

`--env NAME` without a value passes the variable on from your shell, so neither the API key nor a password appears in the command. Pass every variable the identities file names. `--cap-drop ALL` and `--security-opt no-new-privileges` remove rights the Verifier does not need.

Further options:

- Add `-it` for questions, hidden password input and the guided run, for example `docker run --rm -it … appsec-verifier /input/appsec-assessment.yaml --output /output/project`.
- To let the test agent read the source code, mount it read-only and pass it with `--source`: `--volume /path/to/project:/source:ro` and `--source /source`.
- A login program runs inside the container with the image's Python 3.12, from the directory of the identities file. Keep it next to that file.
- `preflight` checks the same files before a run, and `preflight --offline` does so without contacting anything.

## A target on the same machine

Inside the container, `localhost` is the container itself. On Linux, `--network host` puts the container into your machine's network, so `--url http://localhost:3000` reaches a target running there:

```sh
docker run --rm --network host \
  --user "$user" --cap-drop ALL --security-opt no-new-privileges \
  --env ANTHROPIC_API_KEY \
  --volume /path/to/input:/input:ro \
  --volume "$HOME/verifications":/output \
  appsec-verifier verify --non-interactive --yes --profile claude \
  --assessment /input/appsec-assessment.yaml --url http://localhost:3000 \
  --cost-limit 5 --output /output/project
```

With `--network host` the target can also reach the listener for SSRF findings, and a browser sign-in (`oidc-authorization-code`) can return to the Verifier. Without it the container reaches your machine only at a private address, such as `host.docker.internal` with Docker Desktop. The scope file must then allow that address in `networks`, and SSRF findings stay `inconclusive` (see [SSRF](specification.md#proof-per-class-ver-009-to-ver-013)).

The results contain evidence about the tested application. Restrict access to the result directory, and delete it when you no longer need it.
