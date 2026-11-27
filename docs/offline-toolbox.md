# Offline Toolbox (Docker Sandbox) Design

Related: [Offline Knowledge Search Design](offline-knowledge-search.md)

## 1. Background and Problem

In an offline environment, when the agent cannot find a penetration testing tool it needs
inside the container, it tries to obtain it with `apt-get install` / `pip install` /
`git clone` and the like. This causes the following problems.

1. **Outbound attempts that offline mode does not stop** — `offline.GuardDial` gates only
   platform-owned traffic (LLM calls, notifications). Downloads launched from Bash are not
   covered:
   - Tools that honor `HTTP(S)_PROXY` / `ALL_PROXY` (pip, git, curl, npm, go, …) go through
     the recording proxy (`traffic`), whose upstream dial is not offline-gated today. The
     knowledge search design adds that gate ([offline-knowledge-search.md](offline-knowledge-search.md)
     §4.5).
   - Tools that ignore the proxy variables, or open raw sockets, connect directly; **no Go
     dial hook can stop them**.

   If the host has an external network, the download can succeed. If it does not, the model
   gets little insight into why the download failed and wastes turns trying other routes. →
   The fundamental fixes are network isolation (§6.4) and bringing tools in beforehand.
2. **Downloads are not approval-gated by default** — No rule asks for approval of package
   installs or `git clone` out of the box. The opt-in `hardening/intercept-rules.sql` adds
   `ask` rules for them (`[hardening] Package installation`, `[hardening] git clone`, …), but
   those rules are tripwires with known bypasses, and they are not consulted in target-only
   mode. `intercept.alwaysAllowDenylist` (`intercept/alwaysallow_denylist.go:28-29`) only
   keeps an operator from writing an argv allow rule for package managers; it does not cause
   an approval by itself. Under an online misconfiguration (`ARTEX_OFFLINE=0`) a download
   therefore simply succeeds.
3. **Failure UX** — Today the model gets back only raw errors such as "command not found" or
   "network is unreachable", and has no way to learn the inventory (what is available).

The existing premises are:

- The Dockerfile already bakes tools in at build time:
  - pinned, checksum-verified binaries in `/usr/local/bin` (nuclei, httpx, subfinder, katana,
    ffuf, dalfox), plus sqlmap (`/opt/sqlmap`), enum4linux-ng (`/opt/enum4linux-ng`) and bbot
    (venv in `/opt/bbot`)
  - Debian packages in `/usr/bin` (nmap, hydra, john, hashcat, ncrack, python3-impacket,
    ssh-audit, smbclient / rpcclient, nmblookup / net (samba-common-bin), ldapsearch
    (ldap-utils), …)
  - Node 22 + Playwright/Chromium, and nuclei-templates pinned to a commit at
    `/opt/nuclei-templates`
- Agent processes run as an unprivileged executor (uid 10001, `no-new-privileges`), so
  **system-wide** installs (`apt`, writes to `/usr/local`) are impossible. **User-level
  installs are not**: the executor has a writable home (`<data dir>/exec-home`) and a
  writable run directory, so `pip install --user`, `go install`, a local `npm install`, or
  downloading a release binary all work whenever the network is reachable. Permissions are
  therefore not a substitute for network isolation.
- So the problem is not "building an image from scratch" but **expanding the inventory and
  guiding the agent when a tool is missing**, on top of a real network boundary.

## 2. Approach

1. **"A monolith packed with tools" is not the only answer** — Bringing anything into an
   air-gapped environment goes through physical media, and moving, verifying and building a
   10 GB-class image is a real cost. Also, most tools go unused in any given task and enlarge
   the attack surface.
2. **Recommended: a layered structure of a base + per-category toolboxes** — Keep the
   existing image as the base and deliver purpose-specific toolbox images with `docker load`
   (§4 describes how their contents reach the running container). Share the same "signed
   offline distribution" path as knowledge packs.
3. **Report missing tools quickly, with guidance on what to do** — When a missing tool is
   detected, return an error message that points to the inventory list (`list_tools`)
   instead of attempting an installation.
4. **Single source for search and execution** — nuclei-templates is already managed twice,
   "for execution (baked into the image)" and "for search (knowledge pack index)", so align
   the versions through the pack manifest (the image pins `NUCLEI_TEMPLATES_COMMIT`).

## 3. Comparison of Options

| Option | Description | Decision | Rationale |
| --- | --- | --- | --- |
| 1. Fat image | Distribute a single Kali-style all-in-one image | Partial | Simple, but large transfer cost, build time and attack surface. Kept as an option for small environments |
| 2. Per-category toolboxes | Distribute purpose-specific toolbox images as signed archives, `docker load` them, and mount their contents read-only into the ARTEX container (§4) | **Adopted** | Bring in only what is needed. No rebuild of the base image |
| 3. Local package mirror | Run apt-mirror/devpi/pip-proxy inside the closed network | Optional (opt-in) | Operators can add tools freely, but it adds infrastructure for mirror setup, sync and trust management. Not the default; only the procedure is provided, as an appendix. Enabling it turns off the install refusal of §6.2 |
| 4. Tool packs (tarball distribution) | Extract static binaries + manifest + ed25519 signature into a persistent, read-only toolbox directory | **Adopted** | Adds single-binary tools without rebuilding the image. Shares the knowledge pack mechanism |
| 5. Inventory tool `list_tools` | Expose the list of installed tools as an LLM tool | **Adopted** | The model not knowing "what is available" is the root cause of download attempts |

## 4. Image Layout

```
artex:local                 # base (current Dockerfile as is, existing toolset)
artex-tools-web             # web: wfuzz, arjun, wafw00f, whatweb, gobuster …
artex-tools-ad              # Active Directory (Windows/AD): NetExec, kerbrute, evil-winrm, smbmap, impacket scripts …
artex-tools-binary          # binary/PWN: gdb + pwndbg, ROPgadget, checksec, one_gadget …
artex-tools-brute           # brute force/cracking: john jumbo (the image's Debian john is the core edition)
artex-tools-wordlists       # wordlists only (SecLists etc.) — a dependency shared by all categories
```

- **Contents**: Use NetExec rather than CrackMapExec, which is no longer maintained.
  Debian's `python3-impacket` in the base image installs only five commands
  (`impacket-secretsdump`, `-wmiexec`, `-rpcdump`, `-samrdump`, `-netview`); psexec,
  GetUserSPNs, GetNPUsers, ntlmrelayx and the rest belong in `artex-tools-ad`. The everyday
  SMB/LDAP tools (smbclient, rpcclient, nmblookup, net, ldapsearch, enum4linux-ng) are in the
  base image, since offline an agent cannot fetch them for a first look at a Windows host. Wordlists
  live only in `artex-tools-wordlists`; other boxes depend on it instead of carrying their
  own copies.
- **How toolboxes reach the container**: A separate image cannot add binaries to a running
  container by itself, so each toolbox image is a **content image**. Its tree is
  `/opt/toolbox/<category>/{bin,lib,share}`, and the compose overlay delivers it as follows:

  ```yaml
  services:
    toolbox-web:                     # one-shot init service per box
      image: artex-tools-web:<version>
      command: ["/install", "/toolbox"]   # replaces /toolbox/web with the image's tree
      volumes: ["toolbox:/toolbox"]
    artex:
      depends_on:
        toolbox-web: { condition: service_completed_successfully }
      volumes: ["toolbox:/opt/toolbox:ro"]
  volumes:
    toolbox:
  ```

  On Docker versions that support image mounts, the image can be mounted read-only directly
  instead of copied. The server adds each existing `/opt/toolbox/*/bin` to `PATH` at
  startup; agent processes inherit `PATH` (it is on the executor environment allowlist).
- **ABI compatibility**: Many tools are not static binaries (Python venvs, gdb plugins,
  shared libraries). Toolbox images are built `FROM` the same base image, so Python and libc
  match, and their manifest records the base image version. `list_tools` marks a box whose
  base version differs as incompatible instead of offering it.
- **Tag convention**: `artex-tools-<category>:<version>`. The version matches the pack
  manifest.
- **`docker-compose.tools.yml`**: Ship the overlay above and extend with
  `docker compose -f docker-compose.yml -f docker-compose.tools.yml up -d`.
- **Size estimates** (to be measured on the actual images): each box +0.3–1.5 GB on top of
  the base. Wordlists can reach several GB, so they are kept separate.

## 5. Distribution Path (Unified with Knowledge Packs)

Build in the online environment and physically carry the result into the offline
environment.

```
Build machine (online)                    Offline environment
docker build → docker save → gzip         artex verify → docker load (images)
                                          or
static binaries + manifest.json + sig     artex toolpack import (tarball)
        │                                                │
        └── ed25519 signature (knowledge pack key set) ──┘
```

- **manifest.json**: Pin tool name, version, SHA-256 and target architecture to the same
  standard as the Dockerfile's pinning (digest pins). It also records `kind`
  (`toolbox-image` / `toolpack`), the base image version (§4) and, for images, the expected
  image ID and tags.
- **Keys and kind**: Use the same embedded, `key_id`-addressed key set as knowledge packs.
  The verifier checks `kind`, so a validly signed knowledge pack can never be accepted as a
  tool pack. This matters because tool packs contain executables.
- **Verification**: Verification needs the key embedded in the binary, so it runs through
  the artex binary from the already-trusted base image, e.g.
  `docker run --rm -v "$PWD:/in:ro" artex:local /app/artex verify /in/<file>`.
  `scripts/load-toolbox.sh` wraps this and runs `docker load` only after it passes.
- **After `docker load`**: A loaded archive can carry arbitrary repository tags and would
  silently retag existing images (including `artex:local`). The script therefore checks that
  the loaded image ID matches the manifest and that only the expected `artex-tools-*` tags
  were created or moved.
- **Architecture**: Refuse an image or tool pack whose target architecture differs from the
  host's.
- **SBOM**: Attach an SBOM (from syft or similar) to each image and record it at import.

## 6. Handling Missing Tools at Runtime

### 6.1 `list_tools` Tool (toolcatalog Addition)

- **Behavior**: Return names, versions, locations and purpose tags (web / ad / brute …) from
  manifests, without running any tool:
  - an inventory file the Dockerfile writes at build time (it already knows the pinned
    versions and the apt package list)
  - the toolbox manifests under `/opt/toolbox/*/`
  - installed tool packs

  Check only that each listed executable exists, and build the list once at startup.
  Running every binary with `--version` would be slow, and it would execute code as the
  server (root) at startup.
- **Binding**: `planner` and `worker` by default (planning needs the inventory as much as
  execution does), via `ToolSeed.Agents`. Add it to `toolRAGCore` so the Tool RAG projection
  never hides it.
- **Effect**: Because the model plans with knowledge of the inventory, the very idea of "it's
  missing, so install it" comes up less often.
- **Prompt**: When offline, state explicitly in the planner/worker system prompt: "Check
  available tools with `list_tools`. Installing software is not possible (no network)."
  Append it as a code-owned tail, like the untrusted-content block, so a DB prompt override
  cannot drop it.

### 6.2 Stronger Refusal in intercept

- **Install commands**: In offline mode, **automatically refuse** package installs (`pip` /
  `python -m pip` / `uv pip` / `pipx install`, `npm i` / `npx`, `go install` / `go get`,
  `gem install`, `cargo install`, `apt(-get) install`, …). Include in the error message:
  "Check the inventory with `list_tools`. Installation is not possible in an offline
  environment."
  - **Reuse what exists**: The regex of the `[hardening] Package installation` rule and its
    tests (`hardening/rulecheck_test.go`) already cover these commands.
  - **Code-owned, not opt-in**: Make it a code-owned rule evaluated while
    `offline.Enabled()` with action `deny`, rather than an opt-in SQL row, so that it cannot
    be forgotten and also applies in target-only mode.
  - **Why `deny` rather than `ask`**: Offline, the install would fail even if approved, so
    failing early with a clear reason saves turn budget. It is a tripwire for UX, not a
    boundary.
  - **Mirror exception**: When a local package mirror (option 3) is configured, this refusal
    is off.
- **No destination parsing for `curl` / `wget` / `git clone`**: Do not refuse these in
  intercept based on a destination parsed from the command line.
  - They are everyday tools against in-scope targets (and a local git server), so parsing
    would produce false positives.
  - Parsing is easy to bypass anyway.
  - Destinations are decided at the network layer instead: the recording proxy's offline
    gate refuses non-local destinations with the same guidance
    ([offline-knowledge-search.md](offline-knowledge-search.md) §4.5), and network isolation
    (§6.4) drops the rest.

### 6.3 Division of Roles in Defense in Depth

| Layer | Responsibility | Example |
| --- | --- | --- |
| list_tools / prompt | Keep the model from thinking about downloading in the first place | Awareness of the inventory at planning time |
| intercept | Drop install commands with a reason (saves turns) | `pip install` → immediate refusal + guidance |
| Recording proxy gate | Refuse proxy-honoring downloads with a reason (saves turns) | `git clone https://github.com/…` → refused at the proxy + guidance |
| **Network isolation (§6.4)** | **The true last line of defense** | Download attempts that slip through physically cannot reach the network |

> **Correction**: `offline.GuardDial` gates only platform-owned LLM/notification dials and
> does not stop Bash download commands (`curl`/`git clone`, etc.). Therefore the "last line
> of defense for what slips through" is not GuardDial but **network isolation of the
> container** (§6.4). list_tools, the intercept refusal and the proxy gate are not security
> boundaries but layers for saving turns and improving UX.

### 6.4 Network Isolation (the True Last Line of Defense)

The only way to reliably stop downloads is **to make it impossible for the container that
runs the tools to reach anything but local networks**. Not command refusal, not GuardDial:
this is the real boundary.

- **Current gap**: `docker-compose.yml` has no network isolation (no `networks:`
  definitions, no iptables/firewall). The container can reach outside through the default
  bridge.
- **Destinations needed when offline**: ARTEX needs to reach the local LLM (on the host or
  the LAN), Postgres, and the targets, which are on the LAN in an offline setup. The general
  internet is not needed.
- **Why not an `internal: true` Docker network**: It looks like the obvious fix but breaks
  three things:
  - **Targets**: it drops all traffic leaving the Docker network, so LAN targets become
    unreachable, not just the internet.
  - **Port publishing**: published ports do not work for a container attached only to an
    internal network, so the web UI (8787) and the proxy port (8788) become unreachable from
    the host.
  - **Host LLM**: reaching an LLM on the host through `host.docker.internal` is not
    dependable there (and on Linux it needs `extra_hosts: host-gateway`, which the compose
    file does not set).
- **Countermeasure (offline-only overlay)**: Add `docker-compose.offline.yml`, which turns
  on an **egress firewall inside the ARTEX container's network namespace**.
  - **Rule set**: allow loopback, RFC1918 / ULA private ranges (the same set as
    `offline.IsLocalIP`) and the operator's `ARTEX_OFFLINE_ALLOW_CIDRS`; drop everything
    else, including link-local (cloud metadata). This keeps Postgres, the LLM, LAN targets and
    the published ports working.
  - **Where it is applied**: the entrypoint (`start.sh`, still root) applies the rules on
    every start, before the server starts. The overlay adds `cap_add: [NET_ADMIN]` for this.
    Agent processes run as a non-root uid with `no-new-privileges`, hold no capabilities, and
    therefore cannot change the rules. The image needs `iptables` or `nftables`, which it
    does not install today.
  - **Fail closed and visible**: in offline mode, if the rules cannot be applied, the start
    stops, unless the operator explicitly accepts a degraded start. The server checks the
    rule set at startup and reports it in `GET /api/health`, and the web UI shows it as a
    banner, like the existing agent-isolation status.
  - **Start command**: `docker compose -f docker-compose.yml -f docker-compose.offline.yml
    up -d`.
  - **Alternative for Linux hosts**: rules in the host's `DOCKER-USER` chain for a fixed
    compose subnet. These sit outside the container but need host root and per-host setup.
    The in-container approach also works under Docker Desktop.
- **Granularity caveat**: `--network none` goes too far, cutting off Postgres/LLM/targets as
  well. **When not offline**, ARTEX needs to reach arbitrary targets (including the
  internet), so this isolation is **limited to the offline-only overlay**, and the default
  compose file is not changed. The firewall only enforces "no internet"; which LAN hosts may
  be tested is still decided by the target scope and the intercept gate.
- **Effect**: Whatever the agent tries with `apt/pip/git clone/curl`, **the download
  physically cannot succeed**. §6.1/§6.2 are reduced to the role of "cutting wasted turns"
  on top of this boundary.

## 7. Configuration

Follow the existing conventions: deployment switches are environment variables (`ARTEX_*` in
`.env` / docker-compose). `config.json` holds only the database, `skill_dir` and
`task_user_agents`, so no `toolbox` section is added there.

| Setting | Where | Default |
| --- | --- | --- |
| `ARTEX_TOOLBOX_DIR` | Environment | `/opt/toolbox` (toolbox images and tool packs; read-only to agents) |
| `ARTEX_DENY_INSTALLS` | Environment | On while offline mode is on; set `0` when a local package mirror (option 3) is used |
| `ARTEX_OFFLINE_ALLOW_CIDRS` | Environment | Empty; extra ranges for the egress firewall (§6.4), shared with the knowledge search gates |

- `ARTEX_DENY_INSTALLS` enables the automatic refusal in §6.2.
- `list_tools` reads the build-time inventory plus the manifests under `ARTEX_TOOLBOX_DIR`.
  Tools added by images (option 2) and by tarballs (option 4) are merged into the same list.
- Tool packs (option 4) are extracted under `ARTEX_TOOLBOX_DIR` on a persistent volume,
  owned by root and not writable by the executor uid, not into the image's `/usr/local/bin`.
  Files written there would be lost when the container is recreated, and they would mix with
  the base image's pinned binaries.

## 8. Implementation Phases

**Status (2026-11-27)**: Phase 1 is implemented.

- **Egress firewall**: `offline-firewall.sh`, `start.sh`, `docker-compose.offline.yml`;
  `iptables` added to the image. The state is reported in `GET /api/health` and shown as a
  web UI banner.
- **`list_tools`** (`agent/listtools.go`):
  - It reads the build-time inventory that `scripts/tool-inventory.sh` writes.
  - It is bound to planner, worker and the main agent; the main agent runs Bash too.
  - It is built on each call, which is cheap and needs no execution.
- **Offline prompt block**: added to the planner, worker, main-agent and chat prompts.
- **Install refusal** (`guard/offline_install.go`):
  - It is not written to the intercept history, because a rule-less entry there would be
    attributed to the model judge. The block is in the guard's audit ring and the tool
    result.
- **Verification in a real container**:
  - Public addresses, public names, link-local and raw TCP are refused at once.
  - LAN services stay reachable.
  - uid 10001 cannot change the rules.
  - The allow-list works.
  - Without NET_ADMIN the start is refused, and `ALLOW_DEGRADED` overrides that.
  - `ARTEX_OFFLINE=0` skips the firewall.

1. **Phase 1**: Egress firewall via `docker-compose.offline.yml` (§6.4, the true last line
   of defense, with the health/banner report), `list_tools` built from the build-time
   inventory (option 5), and the code-owned offline install refusal (§6.2). Takes effect with
   the existing image plus `iptables`/`nftables`.
2. **Phase 2**: `docker-compose.tools.yml` with the init-service delivery of §4, and the
   first boxes (web + wordlists). Signature-verified `docker load` via
   `scripts/load-toolbox.sh` (`artex verify` + image ID/tag check).
3. **Phase 3**: Tarball-format tool packs (option 4) and the `toolpack import` API. Share
   the key set and manifest format (with `kind`) with knowledge packs.
4. **Phase 4**: Build out the ad / binary / brute categories, SBOM recording, and the local
   package mirror procedure as an appendix (option 3).

## Revision Notes (2026-11-27)

Review against the code on branch `feat/offline-local-llm-only`:

- **Download gating**: package installs are approval-gated only by the opt-in hardening
  rules; `alwaysAllowDenylist` only forbids always-allow rules.
- **User-level installs**: the executor has a writable home, so `pip --user` / `go install`
  etc. work without root. Permissions do not replace network isolation.
- **Recording-proxy path**: added the Bash proxy path and its gate (see the knowledge search
  design §4.5).
- **`internal: true` replaced**: that network type cuts off LAN targets and published ports,
  and does not dependably reach the host LLM. It is replaced by an in-container egress
  firewall with fail-closed start and health reporting.
- **Toolbox delivery**: specified how toolbox images reach the container (content image →
  read-only volume) and base-image ABI compatibility.
- **Pack verification**: verification goes through the artex binary (embedded key),
  manifests carry `kind`, and loaded image IDs/tags are checked after `docker load`.
- **`list_tools`**: reads manifests instead of executing binaries. The baked inventory
  spans `/usr/local/bin`, `/usr/bin` and `/opt`, not just `/usr/local/bin`.
- **Install refusal**: made code-owned (it also applies in target-only mode), reuses the
  hardening regex, and is turned off when a mirror is used. `curl` / `wget` / `git clone`
  are no longer refused by parsing the command line.
- **Tool lists**: NetExec instead of CrackMapExec; removed duplicates (impacket and ffuf are
  already in the base image, SecLists appeared twice); john jumbo.
- **Configuration**: now environment variables instead of a `config.json` section. Tool packs
  go to a persistent directory instead of `/usr/local/bin`.
