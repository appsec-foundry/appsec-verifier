# Run the Verifier in a container

The container image runs one `appsec-verifier` command and exits. The image opens no network port and contains no credentials; you supply them when the container starts.

## What the image contains

- The Verifier from the checkout you build, with the version stamp of that checkout.
- Python 3.12 with the packages of [`requirements.lock`](../requirements.lock), and Claude CLI 2.1.311. The profiles `claude`, `anthropic-api` and `codex` work with their API credentials.

The image leaves out:

- The proof browser. Chrome starts only in a network namespace of its own, which a container with default restrictions cannot create. In the container XSS findings cannot be confirmed and no screenshots are taken; the other classes do not need the browser. To confirm XSS findings, run the Verifier from an [installation](../README.md#install) outside a container.
- Codex CLI and Copilot CLI, so the `codex-cli` and `copilot-cli` profiles do not work in the container.
- Your Claude login. A login made with `claude auth login` on your machine does not carry into the container. Use `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`.
- `update`. To update, build the image again from an updated checkout.

## Build the image

You need Docker or Podman and network access to Docker Hub, Debian, PyPI, and the npm registry. The build checks the base image, the Python packages, and Claude CLI against digests and hashes pinned in the [Dockerfile](../Dockerfile) and in [container/requirements.txt](../container/requirements.txt). The build tools curl and git are pinned by version; apt checks them and their dependencies against Debian's signed package lists. The image supports `amd64` and `arm64`.

Run in the Verifier checkout:

```sh
docker build -t appsec-verifier .
```

To build with Podman, replace `docker` with `podman`; the run examples below are written for Docker.

The image contains only files that Git tracks. Uncommitted changes to them go into the image, and `--version` then shows `+local changes`. Files that Git ignores or does not track, such as results in `verification/`, stay out. Build in a checkout or a clone. In a git worktree the build stops, because the worktree keeps its Git data outside the build context.

## Run with Docker

Mount the assessment, the scope file and the identities file read-only, and a result directory writable. The user in the container must be able to write to the result directory. Which user that is depends on how Docker runs:

- Docker as a system service: your own user ID with group 0, `--user "$(id -u):0"`.
- Rootless Docker, where `docker info` lists `rootless` under security options: `--user 0:0`. Root in the container is then your own user and has no additional rights on your machine.

This command sets the right value for either case:

```sh
if docker info --format '{{.SecurityOptions}}' | grep -q rootless; then user=0:0; else user="$(id -u):0"; fi
```

This example verifies the High and Critical findings of an assessment against a target on another machine, with the `claude` profile and a cost limit of USD 5:

```sh
mkdir -p "$HOME/verifications"
docker run --rm --name appsec-verification \
  --user "$user" --cap-drop ALL --security-opt no-new-privileges \
  --env ANTHROPIC_API_KEY --env USER_A_PASSWORD --env USER_B_PASSWORD \
  --volume /path/to/input:/input:ro \
  --volume "$HOME/verifications":/output \
  appsec-verifier verify --non-interactive --yes --profile claude \
  --assessment /input/security-assessment.yaml \
  --scope /input/scope.yaml --identities /input/identities.yaml \
  --min-severity high --cost-limit 5 --output /output/project
```

Replace `/path/to/input` with the directory that holds the three files. `--cap-drop ALL` and `--security-opt no-new-privileges` take away rights that the Verifier does not need. `--env NAME` without a value passes the variable from your shell, so neither the API key nor a password appears in the command; pass every variable the identities file names in a `*_env` field. The report is written to `$HOME/verifications/project`. Always pass `--output` on a mounted directory: without it, the Verifier writes into the container, and the results are lost when it exits.

Further options:

- For questions, hidden password input and the guided run, add `-it`, for example `docker run --rm -it … appsec-verifier /input/security-assessment.yaml --output /output/project`.
- To give the test agent the source code, mount it read-only and pass it: `--volume /path/to/project:/source:ro` and `--source /source`.
- A login program runs in the container, from the directory of the identities file, with the image's Python 3.12. Keep it next to the identities file.
- `preflight` checks the same files before a run, `preflight --offline` without contacting anything.

## A target on the same machine

In the container, `localhost` is the container itself. On Linux, run the container in the network of your machine with `--network host`, and `--url http://localhost:3000` reaches a target there:

```sh
docker run --rm --network host \
  --user "$user" --cap-drop ALL --security-opt no-new-privileges \
  --env ANTHROPIC_API_KEY \
  --volume /path/to/input:/input:ro \
  --volume "$HOME/verifications":/output \
  appsec-verifier verify --non-interactive --yes --profile claude \
  --assessment /input/security-assessment.yaml --url http://localhost:3000 \
  --cost-limit 5 --output /output/project
```

With `--network host` the target also reaches the callback listener for SSRF findings, and a sign-in with `oidc-authorization-code` can return to its loopback redirect. Without it, the container reaches your machine only at a private address, such as `host.docker.internal` with Docker Desktop; a scope file must then allow that address in `networks`, and SSRF findings stay `inconclusive` (see [SSRF](cli.md#proof-per-class-ver-009-to-ver-013)).

Results contain evidence about the tested application. Restrict access to the result directory, and delete it when you no longer need it.
