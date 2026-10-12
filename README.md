# Sandboxing AI Agents in Docker

Oct 12, 2026 · @Niko Korhonen

## Why sandbox an agent, and against what

An AI agent that runs shell commands, edits files and fetches URLs is an untrusted process, and should get the same treatment you would give any binary you did not write. The model is not the adversary; whatever the model reads is. A README, a web page or a test fixture can carry instructions, and the agent will act on them with every permission its process has.

The sandbox in this tutorial defends against three failure modes:

1. **Prompt injection** — content the agent reads tells it to exfiltrate `~/.ssh`, `~/.aws` or an API key, or to `curl` a payload.
2. **Honest mistakes** — the agent runs `rm -rf` one directory too high, overwrites a config outside the project, or pushes to the wrong remote.
3. **Compromised tooling** — a malicious npm or pip package pulled in by the agent's own work executes a postinstall hook.

It does not defend against kernel exploits. A Docker container shares the host kernel, so a container escape is a kernel bug away. That is an acceptable residual risk for a developer workstation; the last section covers gVisor and microVMs if it is not.

The design is three layers, each of which holds on its own:

| Layer | Controls | Answers |
| --- | --- | --- |
| Image | Non-root user, no sudo, no setuid binaries | Who is the agent? |
| Runtime flags | Dropped capabilities, no new privileges, read-only root, resource limits | What can the process do? |
| Mounts and network | Explicit bind mounts, tmpfs scratch, egress allowlist | What can it reach? |

## Building the image

Install tooling as root at build time, then switch to a fixed-UID user and never come back. The agent needs a real shell, git and a language runtime, so a distroless base is impractical; `debian:bookworm-slim` is small enough and apt keeps the toolchain current.

Three choices in the Dockerfile matter more than the rest:

- **Fixed UID, high number.** `10001` avoids colliding with host users and makes bind-mount ownership predictable. Pass `--build-arg UID=$(id -u)` instead when the agent must write files you own on the host.
- **No sudo, no setuid.** Do not install `sudo`. Strip the setuid and setgid bits from every binary in the image so `no-new-privileges` has nothing left to guard against (`su`, `passwd`, `mount` and `chsh` all carry them by default).
- **Writable home on a known path.** The agent's config and cache live under `/home/agent`; at runtime that path is a volume or tmpfs, because the root filesystem will be mounted read-only.

```dockerfile
FROM debian:bookworm-slim

ARG UID=10001
ARG GID=10001

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git openssh-client ripgrep jq \
      nodejs npm golang-go \
    && rm -rf /var/lib/apt/lists/* \
    # strip setuid/setgid bits from everything; nothing in here needs them
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null

# the agent itself; swap for whatever you run
RUN npm install -g @anthropic-ai/claude-code

RUN groupadd -g ${GID} agent \
    && useradd -m -u ${UID} -g ${GID} -s /bin/bash agent

USER agent
WORKDIR /work
ENV HOME=/home/agent

ENTRYPOINT ["claude"]
```

Run the setuid strip as the last step of the package layer, not in a separate `RUN`, so a later `apt-get` cannot quietly reintroduce the bits. Pin the base image by digest once the image is stable; an unpinned `bookworm-slim` is a supply-chain surface of its own.

## Runtime hardening flags

The image decides who the process is; these flags decide what that process can do, and they apply to any image. Set every one of them; the defaults Docker ships are tuned for compatibility, not containment.

| Flag | What it removes | Why it matters for an agent |
| --- | --- | --- |
| `--user 10001:10001` | Root inside the container, even if the image forgets `USER` | Belt and braces; the image already sets it |
| `--cap-drop=ALL` | All 14 capabilities Docker grants by default (`CHOWN`, `NET_RAW`, `SETUID`, …) | A non-root process rarely needs any; `NET_RAW` alone enables packet sniffing and spoofing |
| `--security-opt no-new-privileges` | Gaining privileges through setuid or file capabilities on exec | Blocks the classic escalation path even if a setuid binary slips into the image |
| `--read-only` | Writes anywhere on the root filesystem | Postinstall hooks and "helpful" edits to `/etc` or `/usr/bin` fail loudly |
| `--tmpfs /tmp:rw,noexec,nosuid,size=512m` | Persistent scratch, and execution from scratch | Downloaded binaries cannot run from `/tmp` |
| `--pids-limit 512` | Unbounded process creation | Fork bombs and runaway test suites stop at a number, not at the host's limit |
| `--memory 4g --cpus 2` | Unbounded RAM and CPU | A stuck build cannot starve the host or your inference GPU |
| `--security-opt seccomp=default.json` | \~44 syscalls (`mount`, `ptrace` across users, `kexec_load`, `reboot`, …) | This is Docker's default profile; naming it explicitly stops `--privileged` or a compose override from silently removing it |
| `--init` | Orphaned zombies when the agent spawns subprocesses | Not security, but agents fork constantly and tini reaps for free |

Two flags look tempting and are wrong here:

- `--privileged` undoes every row in the table at once. Nothing an agent does needs it.
- `--cap-add` of anything. If the agent's work needs `NET_ADMIN` or `SYS_PTRACE`, do that work in a separate container with its own smaller blast radius.

AppArmor needs no flag: on Ubuntu and Debian hosts Docker applies its `docker-default` profile automatically, and `--security-opt apparmor=unconfined` is the only way to lose it. Check with `aa-status` on the host that the profile is loaded; a fresh VPS image occasionally ships without AppArmor enabled.

## Filesystem access

The rule is one writable mount: the project the agent is working on. Everything else is read-only, ephemeral or absent.

| Path in container | Source | Mode | Why |
| --- | --- | --- | --- |
| `/work` | `./my-project` bind mount | rw | The only thing the agent is supposed to change |
| `/ref` | `../shared-lib`, docs, fixtures | ro | Context it may read but must not edit |
| `/home/agent` | named volume `agent-home` | rw | Agent config, auth cache, shell history; survives container restarts |
| `/tmp` | tmpfs | rw, noexec | Scratch that disappears with the container |
| `/home/agent/.cache` | tmpfs | rw | npm, pip and Go module caches; rebuilt on demand |

Never mount these, whatever the agent claims it needs:

- `$HOME` or `/` from the host — one bind mount of your home directory defeats the whole exercise.
- `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.gitconfig` with credentials in it — if the agent can read a key, so can anything it reads.
- `/var/run/docker.sock` — the socket is root on the host, full stop. An agent that "needs Docker" needs a sidecar with a scoped API, or nothing.

**Ownership.** Files the agent creates in `/work` are owned by UID 10001 on the host. Either build the image with `--build-arg UID=$(id -u)` so that matches you, or enable user-namespace remapping on the daemon (`userns-remap` in `daemon.json`), which maps container UID 0 to an unprivileged host range and makes even an escaped root harmless. Remapping is the stronger option; the price is that bind-mounted files need their ownership shifted once with `chown`.

**Secrets.** The agent needs its model API key and nothing else. Pass it with `--env-file agent.env` containing only that key, scoped as narrowly as the provider allows, and rotate it on a schedule. Keep git credentials out: let the agent commit locally, and push from the host where your keys live. If the agent must talk to a private registry, give it a read-only deploy token with an expiry, not your personal one. The key is visible to the agent process by design; the point is that it is the only thing that is.

## Network restriction

Put the agent on a Docker network with no route out, and give it one door: an HTTP proxy that only forwards to an allowlist. The agent needs the model API, usually a git host, and perhaps a package registry; everything else is exfiltration surface.

&#91;embedded content: agent network · one proxy, four allowed hosts\]

The agent and the proxy share the internal network; only the proxy also sits on a network with a route out, and it forwards solely to the allowlist.

The pieces:

1. **An internal network.** `docker network create --internal agent-net` (or `internal: true` in compose). Containers on it can talk to each other and resolve each other's names through Docker's embedded DNS, but have no default route and no external DNS.
2. **A proxy sidecar on two networks.** It sits on `agent-net` and on the default bridge, so it alone can reach the outside. It resolves hostnames itself, which is why the agent needs no DNS of its own.
3. **Proxy environment in the agent.** `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` set to the sidecar. Go's `net/http`, Python `requests`, `curl`, `git` and `npm` all honor these; Claude Code honors `HTTPS_PROXY` as well. A tool that ignores them simply fails to connect, which is the correct outcome.

Tinyproxy is enough for the sidecar; a dozen lines of config and an allowlist file:

```text
# tinyproxy.conf
Port 8888
Listen 0.0.0.0
Allow 172.16.0.0/12
ConnectPort 443
FilterDefaultDeny Yes
FilterExtended On
FilterURLs Off
Filter "/etc/tinyproxy/allowlist"
LogLevel Connect
```

```text
# allowlist — one extended regex per line, matched against the host
^api\.anthropic\.com$
^github\.com$
^registry\.npmjs\.org$
^proxy\.golang\.org$
^sum\.golang\.org$
```

`FilterURLs Off` matches the hostname rather than the full URL, which also covers `CONNECT` tunnels for HTTPS. Option names shifted between Tinyproxy 1.10 and 1.11 (`FilterType` replaced `FilterExtended`), so check `man tinyproxy.conf` on the version your image ships. The `LogLevel Connect` line gives you one log line per destination, which is the audit trail of everything the agent tried to reach.

**Local models.** If the agent should use Ollama on the LAN or over Tailscale, the proxy can reach it because the proxy's second network has a route to the host's networks. Add the Ollama host to the allowlist and point the agent at `http://ollama.tail1234.ts.net:11434`; plain-HTTP requests go through the proxy as ordinary `GET`s, so no extra `ConnectPort` is needed. Keep `NO_PROXY` empty, or the client will bypass the proxy and find no route.

**Fully offline.** For refactoring or test runs with a local model you have already pulled, `--network none` is simpler than any allowlist and leaves nothing to audit.

**When the proxy is not enough.** A tool that opens raw sockets or ignores proxy variables needs packet filtering, not an application proxy. Run a second sidecar with `network_mode: "service:agent"` and `cap_add: [NET_ADMIN]` that installs an nftables allowlist into the shared network namespace at startup, then exits. The agent container itself still runs with every capability dropped; only the short-lived sidecar holds `NET_ADMIN`.

## Putting it together

One compose file carries every control from the sections above, so `docker compose run agent` is the only command to remember. The example runs Claude Code against a Go project; replace the entrypoint and the allowlist for any other agent.

```yaml
# compose.yaml
services:
  agent:
    build:
      context: .
      args:
        UID: ${UID:-10001}
        GID: ${GID:-10001}
    user: "${UID:-10001}:${GID:-10001}"
    working_dir: /work
    stdin_open: true
    tty: true
    init: true
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
      - seccomp:default.json
    pids_limit: 512
    mem_limit: 4g
    cpus: 2
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=512m
      - /home/agent/.cache:rw,size=2g
    volumes:
      - ./my-project:/work
      - ../shared-lib:/ref/shared-lib:ro
      - agent-home:/home/agent
    env_file: agent.env            # ANTHROPIC_API_KEY=... and nothing else
    environment:
      HTTP_PROXY: http://proxy:8888
      HTTPS_PROXY: http://proxy:8888
      NO_PROXY: ""
      GOFLAGS: -mod=mod
      GOCACHE: /home/agent/.cache/go-build
      GOMODCACHE: /home/agent/.cache/go-mod
    networks: [agent-net]
    depends_on: [proxy]

  proxy:
    image: ghcr.io/example/tinyproxy:1.11   # any tinyproxy image; alpine + apk add tinyproxy works
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    user: "65534:65534"
    tmpfs: [/tmp, /var/log/tinyproxy]
    volumes:
      - ./proxy/tinyproxy.conf:/etc/tinyproxy/tinyproxy.conf:ro
      - ./proxy/allowlist:/etc/tinyproxy/allowlist:ro
    networks: [agent-net, egress]

networks:
  agent-net:
    internal: true
  egress: {}

volumes:
  agent-home: {}
```

Fetch Docker's default seccomp profile once and keep it next to the compose file, so the `seccomp:` line resolves on any host:

```bash
curl -fsSLo default.json \
  https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json
```

Then:

```bash
export UID GID=$(id -g)
docker compose build
docker compose run --rm agent
```

A few things the file is doing that are easy to miss:

- The Go caches are redirected into the tmpfs under `/home/agent/.cache`, because a read-only root means Go's default `$HOME/.cache` must be writable somewhere, and a 2 GB tmpfs is cheaper than a volume that grows forever.
- The proxy runs as `nobody` with its own capabilities dropped. A sidecar that can reach the internet is the second most valuable target in the setup.
- `agent.env` holds one line. If it holds more, the extra lines are the thing you are leaking.
- `depends_on` does not wait for the proxy to be ready, only started. Tinyproxy starts in well under a second, so this is fine in practice; add a healthcheck if the first request ever races it.

Anthropic maintains a reference devcontainer for Claude Code in the [claude-code repository](https://github.com/anthropics/claude-code) that takes the packet-filter route (an iptables allowlist installed at startup) rather than a proxy sidecar. It is worth reading as a second opinion on the same problem.

## Verifying the sandbox

Run these from a shell inside the container (`docker compose run --rm --entrypoint bash agent`) before trusting it with anything. Each one should produce the expected result; if any does not, the layer it tests is not in place.

| Check | Command | Expected |
| --- | --- | --- |
| Not root | `id -u` | `10001` (or your UID) |
| No capabilities | `grep CapEff /proc/self/status` | `0000000000000000` |
| No privilege escalation | `grep NoNewPrivs /proc/self/status` | `1` |
| No setuid binaries | `find / -xdev -perm /6000 -type f 2>/dev/null` | No output |
| No sudo | `command -v sudo` | Nothing, exit 1 |
| Read-only root | `touch /usr/bin/x` | `Read-only file system` |
| No exec from scratch | `cp /bin/true /tmp/t && /tmp/t` | `Permission denied` |
| No Docker socket | `ls /var/run/docker.sock` | `No such file` |
| Home not mounted | `mount \| grep ' /home'` | Only the `agent-home` volume |
| Allowed egress works | `curl -sI https://api.anthropic.com \| head -1` | An HTTP status line |
| Blocked egress fails | `curl -sI https://example.com` | Proxy returns 403; `curl` exits non-zero |
| No direct route out | `env -u HTTPS_PROXY curl -m 3 https://api.anthropic.com` | Timeout or `Could not resolve host` |
| Process ceiling | `cat /sys/fs/cgroup/pids.max` | `512` |
| Memory ceiling | `cat /sys/fs/cgroup/memory.max` | `4294967296` |
| Seccomp active | `grep Seccomp /proc/self/status` | `2` (filter mode) |

On the host, two more:

- `docker inspect <container> --format '{{.HostConfig.Privileged}} {{.HostConfig.CapAdd}}'` → `false []`
- `aa-status | grep docker-default` → the profile is listed and enforcing

Keep the table as a script in the repo and run it from CI whenever the Dockerfile or compose file changes. A sandbox that was correct last month is a claim, not a fact.

## Going further

The setup above is a strong default for a workstation. Four upgrades close the gaps that remain, in roughly the order they are worth the effort.

| Upgrade | Closes | Cost |
| --- | --- | --- |
| Rootless Docker or Podman | The daemon itself runs as root; a daemon bug or a leaked socket is host root | Rootless Docker needs `dockerd-rootless-setuptool.sh` and loses some networking features; Podman is rootless by default and drop-in for the compose file (`podman compose`) |
| User-namespace remap | Container UID 0 maps to a real host UID 0 if anything ever runs as root | One-time `chown` of bind mounts to the remapped range; `userns-remap` in `daemon.json` |
| gVisor (`--runtime=runsc`) | Shared kernel: syscalls hit a userspace kernel instead of the host | \~10–30 % slowdown on syscall-heavy builds; no GPU passthrough, so local inference stays outside the sandbox |
| MicroVM (Firecracker, Kata) | Everything, including kernel exploits | A separate kernel per agent; heavier tooling and a different mental model |

Three caveats specific to agents:

- **Autonomous mode belongs inside the sandbox only.** Flags such as Claude Code's `--dangerously-skip-permissions` make the agent act without confirmation; that is exactly the mode this container is built for, and exactly the mode that is reckless on the host.
- **Agents that want Docker.** An agent asked to "run the integration tests" will try to reach `docker`. Give it a `docker` CLI pointed at a rootless Podman socket owned by the agent's own UID, or a sidecar exposing a narrow API, or tell it no. Never the host socket.
- **The sandbox is not a review.** A contained agent can still write a backdoor into `/work` that you then merge and deploy. The container bounds the blast radius during the session; code review bounds it after.
