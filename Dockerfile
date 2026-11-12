# Container image for the appsec-verifier command. Usage: docs/container.md
#
# The base image, Python packages, and Claude CLI are pinned by digest or hash,
# the named Debian packages by version; apt resolves their dependencies from
# Debian's signed package lists. To update a pin, change its version and its
# digest or hash together, rebuild, and run tests/test_container_smoke.py.
# Dependabot proposes base image updates; container/check_pins.py reports newer
# Debian packages and Claude CLI releases. The Python packages keep the versions
# of requirements.lock and are raised there first.
# - Base image: digest of the Docker Hub tag python:3.12.x-slim-trixie.
# - Debian packages: versions from https://packages.debian.org/trixie/.
# - Python packages: container/requirements.txt, container/build-requirements.txt.
# - Claude CLI: the npm packages @anthropic-ai/claude-code-linux-x64 and
#   -linux-arm64; the hash is the registry's "integrity" value as hex.
#
# Unlike AppSec Analyzer's image, the build stage alone needs Debian packages, and
# the image has no proof browser: Chrome starts only in a network namespace of its
# own, which a container with default restrictions cannot create (VER-009).

FROM python:3.12.16-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore


FROM base AS build

ARG CLAUDE_CLI_VERSION=2.1.311
ARG CLAUDE_CLI_SHA512_X64=764d6554cb7b9fe36562e70a33b74ba7f3dfacadf6a5aff8a0a42469c7dace54a3f2b1be8641faef09c39da146f46b366a5dce8caf0f4d51e06765861d7a1652
ARG CLAUDE_CLI_SHA512_ARM64=c99c039ad5e6a197057028c26a8ce738aaa3ae38dd43273a3d5ba1e9bac036a41c68aa4ff96646b8596052381087ceaef070726c764107ad1658eba62a93bab9

RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
      curl=8.14.1-2+deb13u7 \
      git=1:2.47.3-0+deb13u1 \
 && rm -rf /var/lib/apt/lists/*

# The native Claude CLI binary, checked against its pinned hash. No npm install script runs.
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) platform=linux-x64; sha512="$CLAUDE_CLI_SHA512_X64" ;; \
      arm64) platform=linux-arm64; sha512="$CLAUDE_CLI_SHA512_ARM64" ;; \
      *) echo "Claude CLI has no build for this architecture" >&2; exit 1 ;; \
    esac; \
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output /tmp/claude.tgz \
      "https://registry.npmjs.org/@anthropic-ai/claude-code-${platform}/-/claude-code-${platform}-${CLAUDE_CLI_VERSION}.tgz"; \
    echo "${sha512}  /tmp/claude.tgz" | sha512sum --check --strict -; \
    tar -xzf /tmp/claude.tgz -C /tmp package/claude; \
    install -m 0755 /tmp/package/claude /usr/local/bin/claude; \
    rm -rf /tmp/claude.tgz /tmp/package

COPY container/build-requirements.txt /tmp/build-requirements.txt
RUN pip install --require-hashes --only-binary=:all: -r /tmp/build-requirements.txt

# The build reads .git to stamp the version, as an installation from a checkout does.
COPY . /src
# Only files that Git tracks go into the wheel. setup.py copies whole runtime
# directories, which would otherwise include ignored files. A git worktree keeps
# its Git data outside the build context.
RUN git -C /src rev-parse --git-dir >/dev/null \
 || { echo "Build from a Git checkout or clone, not from a git worktree" >&2; exit 1; }; \
    git -C /src clean -ffdxq
RUN pip wheel --no-deps --no-build-isolation --wheel-dir /wheels /src


FROM base

COPY container/requirements.txt /tmp/requirements.txt
COPY --from=build /wheels/ /tmp/wheels/
RUN pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && pip install --no-deps --no-index /tmp/wheels/*.whl \
 && pip check \
 && rm -rf /tmp/requirements.txt /tmp/wheels

COPY --from=build /usr/local/bin/claude /usr/local/bin/claude

# OpenShift starts containers with a random user ID in group 0, so the home
# directory belongs to group 0 and is group-writable.
ENV HOME=/home/verifier \
    DISABLE_AUTOUPDATER=1
RUN useradd --uid 10001 --gid 0 --home-dir /home/verifier --create-home --shell /usr/sbin/nologin verifier \
 && chmod 0770 /home/verifier

USER 10001
WORKDIR /home/verifier
ENTRYPOINT ["appsec-verifier"]
CMD ["--help"]
