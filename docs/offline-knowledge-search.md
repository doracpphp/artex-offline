# Offline Knowledge Search Design (offline-knowledge-search)

Related: [Offline Toolbox (Docker Sandbox) Design](offline-toolbox.md)

## 1. Background and Problem

Through the `offline` package, ARTEX permits only local LLMs: platform-owned outbound
connections (LLM calls, notifications) to non-local addresses are refused at dial time, and
the update check is switched off. However, the behavior of "using web search to fill in what
the LLM doesn't know" cannot work in an offline environment. Refusing a connection is all a
guard can do; the agent is left stuck without the knowledge it needs.

The problem is not "how to forbid web search" but **how to give the agent, as tools, local
search capabilities of equal or greater value**. The knowledge needed for penetration testing
(exploits, CVEs, attack techniques) is static and can be almost entirely substituted by local
mirrors.

## 2. Guiding Principles

1. **Provide, don't just replace** — Rather than merely blocking web search, add a set of
   local knowledge-search tools to toolcatalog as its substitute. The model is steered to
   satisfy its "I want to search" intent with local tools.
2. **Separate search from lookup** — Free-form technique documentation is handled by search
   (full-text/vector); CVEs and product fingerprints are handled by structured lookup
   (CPE → CVE → EDB-ID).
3. **Knowledge pack model** — Archives are collected, compressed, and signed in an online
   environment, then carried into the offline environment and imported. The offline
   environment itself never collects anything.
4. **Evidence consistency** — Search results always return their source (pack name / file
   path / line or ID) so they can be traced as the basis for a finding.
5. **Defense in depth (with a correct understanding of the guard's reach)** — Three layers:
   tool provisioning (primary), prompt steering (secondary), and egress controls (backstop).
   The heart of the design is "providing substitute tools"; the egress controls are backstop
   insurance. An important premise: today offline mode covers **only platform-owned
   traffic**. `offline.GuardDial` is wired into the LLM client dial (`quotaAwareHTTPClient`)
   and notification delivery; the model-list fetch applies the same local-only policy through
   its own guard (`modelURLGuard`); the update check is simply forced off. The paths by which
   the agent itself reaches outside are separate, and none of them is covered by offline mode
   yet (detailed in §4.5):
   - **WebFetch, enrich probes and the custom HTTP tool** dial through
     `intercept.PinnedDialer`. It confines a connection to the target scope **only while the
     scope's target gate is on**. With the gate off, or for a client built without a scope,
     it dials any address, public ones included.
   - **Commands launched via Bash** receive `HTTP(S)_PROXY` / `ALL_PROXY` pointing at the
     recording proxy (`traffic`), so tools that honor those variables pass through a Go
     dialer that can be gated. A tool that ignores them, or opens a raw socket, connects
     directly, and **no Go dial hook can stop it**. Truly blocking it requires network
     isolation at the OS/container level, which ARTEX does not have today: `hardening` is a
     set of opt-in intercept approval rules and `intercept` is the approval/target gate;
     neither is a network boundary.
   - **`mcphttp`** (external MCP servers) has no offline gate.
   This design therefore includes, as a prerequisite, **additional implementation** of
   offline gating for these paths (§4.5). In a true air-gapped environment there is
   physically no external network, so the gates are positioned not as the "last line of
   defense" but as one layer of defense in depth.

## 3. Options Considered and Decisions

| Option | Description | Decision | Rationale |
| --- | --- | --- | --- |
| A. Local ExploitDB mirror | git clone + search `files_exploits.csv` | **Adopted** | A machine-readable index filterable by EDB-ID/CVE/type/port already exists |
| B. Technique documentation search | Full-text/vector search over PayloadsAllTheThings, HackTricks, WSTG, etc. | **Adopted** | Free-form technique knowledge can only be supplied through search |
| C. NVD/CPE/CWE structured mirror | Store NVD 2.0 snapshots (CVE, CPE, match criteria) locally | **Adopted (recommended)** | Resolves "fingerprint → CVE → EDB" with deterministic joins rather than fuzzy LLM search |
| D. nuclei-templates / MSF metadata | Make template YAML and module info searchable | **Adopted (recommended)** | Search results lead directly to executable artifacts |
| E. MITRE ATT&CK STIX | Technique lookup from Enterprise/ICS STIX bundles | Optional (later phase) | Useful for normalizing technique tags, but moderate initial value |
| F. Progressive skill disclosure | Existing `skills/` index → body read | Adopted (reuses existing mechanism) | No RAG cost; matches the existing SKILL.md conventions |
| G. Hybrid search engine | Postgres full-text search (`tsvector`) + `pg_trgm` + pgvector (embedding) | **Adopted** | Postgres is an existing dependency. Degrades to lexical search alone when pgvector is unavailable |
| H. Knowledge pack distribution | Offline updates via signed archives | **Adopted** | Without an offline update path, the corpus goes stale |
| I. Runtime enforcement | Offline gates on the agent's egress paths (§4.5) + no web-search-like tools + prompt steering | **Adopted** | Mostly an extension of the existing offline package; the direct Bash path additionally needs container network isolation ([offline-toolbox.md](offline-toolbox.md)) |

Rejected / deferred:

- **Pre-summarizing the corpus with a local LLM** — The idea of baking summaries in at pack
  build time. It increases the freshness-management burden and hallucination risk, so raw
  text + search is the baseline; to be considered in the future.
- **EPSS / KEV snapshots** — Useful for prioritization but out of scope for the first
  release. Keep the pack format extensible.
- **External search server via MCP** — The idea of connecting a local MCP through `mcphttp`.
  In-process tools suffice, so we avoid adding another point of failure and configuration
  surface.
- **True BM25 ranking** — Postgres full-text ranking (`ts_rank` / `ts_rank_cd`) is not BM25
  (it has no corpus-wide IDF). True BM25 needs a further extension (e.g. ParadeDB
  `pg_search`), another deployment dependency. Start with built-in ranking and revisit only
  if ranking quality falls short.

## 4. Architecture

```
Online environment                            Offline environment
┌──────────────────────────┐                  ┌────────────────────────────────────────┐
│ artex-knowledge build    │                  │ ARTEX (offline mode)                   │
│  ├ exploitdb (git)       │  signed pack     │  knowledge import → verify → index     │
│  ├ nvd (2.0 snapshot)    │ ── USB/scp ──▶   │   ├ Postgres FTS/trigram (+pgvector)   │
│  ├ PayloadsAllTheThings  │                  │   └ data/knowledge/<pack-id>/          │
│  ├ HackTricks, WSTG      │                  │  agent tools:                          │
│  └ nuclei-templates      │                  │   search_exploits / lookup_cve         │
└──────────────────────────┘                  │   lookup_software / search_technique   │
                                              │   read_knowledge / copy_knowledge_file │
                                              │  egress gates = defense in depth (4.5) │
                                              └────────────────────────────────────────┘
```

### 4.1 Knowledge Packs

A single tar.gz archive (`knowledge-pack-<ver>.tar.gz`):

```
manifest.json          # pack id, version, base version (delta packs only), build time,
                       # sources (upstream version + license), signing key id,
                       # path / size / SHA-256 of every file, deletions (delta packs only)
manifest.sig           # ed25519 signature over manifest.json
exploitdb/             # files_exploits.csv + exploits directory (actual files)
nvd/                   # NVD 2.0 API snapshot (CVE, CPE, match criteria) + CWE dictionary
docs/                  # technique documents (PayloadsAllTheThings, HackTricks, WSTG …)
templates/             # nuclei-templates
embeddings/            # optional: precomputed chunk embeddings (model name, digest, dimension)
index/meta.json        # document type, language, chunking settings
```

- **Verification order**: Verify `manifest.sig` against a trusted key **before reading
  anything else**. Then stream the archive entries, accept only paths listed in the
  manifest, and check each file's size and SHA-256 as it is written. Reject the pack if a
  listed file is missing or an unlisted file is present. The pack is a trust boundary (§7).
- **Safe extraction**: Accept regular files and directories only. Reject symbolic links,
  hard links, device files, absolute paths and `..` components. Cap the total extracted size
  and file count (decompression bombs) and check free disk space before starting.
- **Staging and activation**: Extract into `data/knowledge/.staging/<pack-id>/`, build the
  index, and only then move the directory into place and mark the `kb_packs` row active. A
  failed or interrupted import leaves the currently active pack untouched.
- **Signing key**: **Embedding the ed25519 public key in the binary is recommended** (config
  is mutable, so an attacker who gains write access could swap out the key along with it).
  Embed a small key set addressed by `key_id`, so that a key can be rotated by shipping a new
  binary without invalidating packs signed with the previous key. If the key must be managed
  externally, use TOFU with the operator visually confirming the fingerprint, and detect and
  reject any unauthorized change after the initial pin.
- **Rollback protection**: A validly signed old pack is still stale, and may be known-bad.
  Refuse a pack whose version is lower than the active pack with the same id unless the
  operator explicitly confirms the downgrade.
- **Delta packs**: Carry `base_version` and a deletion list, and apply only on top of an
  active pack of exactly that version.
- **Storage**: Actual files are extracted under `data/knowledge/<pack-id>/`, owned by the
  server and not writable by the executor uid that agent processes run as. Postgres holds
  only the search index and metadata. File paths are always confined under this directory.
- **Import entry points**: Web upload (UI: System → Knowledge), streamed to disk rather than
  buffered. Packs can reach several GB (§5), and browser uploads of that size are fragile,
  so also support importing a file placed on the server (e.g. `data/knowledge/inbox/`) or
  via a CLI subcommand. All entry points share the same verification path.

### 4.2 Search Index (Postgres)

| Table | Role |
| --- | --- |
| `kb_packs` | Pack management (pack id, version, key id, manifest hash, import timestamp, active flag) |
| `kb_documents` | Metadata for documents/exploits in a pack (id, pack_id, kind, source_path, title, cve_ids, cpe_tags, technique_ids) |
| `kb_chunks` | Body chunks + `tsvector` column (GIN index) + trigram index on identifiers |
| `kb_embeddings` | Chunk embeddings (chunk_id, model, dimension, `vector`); **created at runtime** only when pgvector is available (see below) |

> **Premise**: `db/` makes no use of full-text search today, so the FTS foundation is
> **entirely new**. Postgres itself is already a dependency. The schema goes into a numbered
> migration (`db/migrations/NNNN_knowledge.sql`), which `db.Open` applies once and then
> locks by checksum.
>
> - **`pg_trgm`** is a contrib module shipped in the stock `postgres:16-alpine` image, so
>   `CREATE EXTENSION IF NOT EXISTS pg_trgm` can live in that migration.
> - **pgvector is not shipped, and must not go in that migration.** On the stock image the
>   migration would fail and block startup, and a migration guarded by an availability check
>   would never run again once pgvector is installed later. Instead, the knowledge package
>   creates the `vector` extension and `kb_embeddings` at runtime when
>   `pg_available_extensions` lists `vector`; otherwise the vector path stays disabled.
> - **Enabling pgvector is a deployment change**: replace the digest-pinned
>   `postgres:16-alpine` with a digest-pinned pgvector image of the **same major version
>   (pg16)** so that the existing `pgdata` volume still works. Moving from the Alpine (musl)
>   image to a Debian (glibc) based image changes collation behavior, so text indexes must be
>   rebuilt with `REINDEX` after the switch. The alternative is to build pgvector into an
>   Alpine-based image. With an external database (`ARTEX_PG_DSN`), the role may not be
>   allowed to create extensions; the feature then runs lexical-only and says so in the UI.

- **Lexical search**: `tsvector` with a GIN index, ranked with `ts_rank_cd`. The security
  corpus is predominantly English, so docs/ uses the `english` configuration, while
  identifiers (CVE, CPE, function names, payload symbols) use `simple` together with
  `pg_trgm` to catch symbols and partial matches. Postgres tokenizes the documents; for
  query preprocessing (lowercasing, splitting identifiers) the tokenizer in the existing
  `agent/toolrag.go` can be reused.
- **Vector**: pgvector (HNSW). For embeddings, add an "embedding" role to the existing LLM
  profile mechanism and have it point at a local server (Ollama `nomic-embed-text`,
  `bge-m3`, etc.). **Note**: The existing providers assume chat-completions; the embeddings
  endpoint (`/v1/embeddings` / Ollama `/api/embed`) is a new provider surface, so the
  implementation effort is larger than "adding one setting". It is also a *separate* endpoint
  from the chat LLM: a chat-only local gateway (e.g. Strata, which serves chat/completions and
  Anthropic messages but no embeddings) cannot provide the vectors, so a deployment that uses
  such a gateway for the LLM runs a dedicated local embedder (Ollama) for the vector half, or
  stays lexical-only. Calls go through a dialer with
  `offline.GuardDial`, like the LLM client (§4.5). A vector column has a fixed dimension, so
  each row records its model and dimension; changing the embedding model means re-embedding.
  Common models (768 / 1024 dimensions) fit within pgvector's 2,000-dimension HNSW limit.
- **Embedding cost**: Embedding a multi-GB corpus on a local server can take hours and
  competes with the chat model for the GPU. A pack may therefore carry precomputed embeddings
  for a named model (name + digest + dimension). Import uses them when the configured
  embedding model matches; otherwise it embeds in the background at low priority, and lexical
  search is available in the meantime. Each search also needs one (short) query embedding.
- **Fusion**: Merge the lexical top k and the vector top k with RRF (Reciprocal Rank Fusion)
  and return the top N. Without the vector path, return the lexical ranking as is.

### 4.3 Agent Tools (toolcatalog Additions)

| Tool | Input | Behavior |
| --- | --- | --- |
| `search_exploits` | Query (keyword/CVE/type/platform) | Hybrid search over the ExploitDB CSV + exploit bodies. Returns EDB-ID, title, type, platform, date, verified flag and path |
| `lookup_cve` | CVE ID | Returns the description, CVSS, CWE, affected products/versions and references from the NVD mirror, plus linked EDB-IDs and nuclei templates when known |
| `lookup_software` | Product name + version (optional vendor / CPE) | Normalizes the fingerprint to CPE candidates, evaluates NVD match criteria including version ranges, and returns matching CVEs with the basis and confidence of each match (§5) |
| `search_technique` | Query (technique, payload, WAF evasion, etc.) | Hybrid search over technique documents under docs/. Returns snippets with source paths |
| `read_knowledge` | document id / source path (+ chunk range) | Returns the full text of a chunk (capped). Progressive disclosure: search → read |
| `copy_knowledge_file` | document id / source path | Copies the file (exploit source, template, wordlist) into the run's working directory so that Bash and the file tools can use it |

Binding: register the tools as toolcatalog seeds (`ToolSeed.Agents`). `search_*` /
`lookup_*` / `read_knowledge` are bound to **both `planner` and `worker`** by default
(knowledge serves action and is needed in both the planning and execution phases).
`copy_knowledge_file` is bound to `worker` only, since the planner has no shell or file
tools. For `mainagent` (chat) and custom agents the tools are not bound by default; the
operator can bind them in System → Tools. When knowledge search is disabled or no pack is
active, the tools are filtered out when tools are resolved, instead of answering "no data"
on every call.

Why `copy_knowledge_file` is needed: the agent's file tools are confined to the run's working
directory (`os.Root`, `agent/filetools.go`), and Bash runs as the unprivileged executor, so
neither can reach `data/knowledge/`. Copying is the only path from a pack to execution, and
running the copied exploit still goes through the normal intercept approvals.

Design rules:

- **Consistent with existing conventions** — Follow the `str()` / schema helpers in
  `agent/tools.go` and the `ToolSeed` registration pattern in `agent/toolcatalog.go`.
  `search_technique` uses the same progressive disclosure as the `skills/` index → SKILL.md
  reading flow (option F).
- **Avoiding name collisions + interference with Tool RAG** — `agent/toolrag.go` already
  exists as "Tool RAG" (a lexical **projection** of the bound tool list). This mechanism is
  something different, so its Go package is named `knowledge`. When `ARTEX_TOOL_RAG` is
  enabled, the projection must not drop the knowledge tools from the catalog, so **add the
  six tool names to `toolRAGCore` explicitly**. `toolRAGCore` is an exact-name map, so a
  `search_*` / `lookup_*` pattern would not work, and as a prefix it would also sweep in the
  existing `search_all_worker_traces` / `search_task_worker_traces`.
- **Citations required** — Every tool's output includes `source: pack-id:path[:chunk]`. The
  model is made to copy this source into the evidence description of findings.
- **Untrusted framing** — Tool results already pass through the untrusted-output boundary
  (nonce-tagged framing, `ARTEX_UNTRUSTED_BOUNDARY`, on by default), so the knowledge tools
  need no framing of their own. They must return corpus text only as a tool result, never
  spliced into a system prompt. Exploit code and technique pages routinely contain imperative
  text ("run this", "now execute …"), which is exactly what the boundary exists for;
  operators who turn the boundary off should know the corpus is then unframed.
- **Limits** — Cap the number of chunks and bytes per response to protect the context budget.

### 4.4 LLM Steering (Discouraging Web Search)

1. **System prompt** — When offline and a pack is active, state explicitly in the
   planner/worker system prompt that "searches are done with the `search_*` / `lookup_*`
   tools. There is no external network." Append it as a code-owned tail, like the
   untrusted-content block (`agent/untrusted_prompt.go`), so that a DB prompt override or an
   operator edit cannot drop it.
2. **Tool design** — Do not register general-purpose tools that look like web search itself
   (search-web, etc.) in the catalog. The existing **WebFetch remains for target
   inspection**, but it is confined to the scope **only while the target gate is on**; with
   the gate off it can fetch any URL, so offline mode needs the additional gate in §4.5.
   Bash curl is **not stopped by GuardDial** (§4.5), so deterrence relies on tool
   provisioning and prompt steering, with network isolation as the backstop.
3. **Guidance on refusal** — When an agent-initiated connection is refused, include guidance
   in the refusal such as "There is no external network. Use the local `search_*` /
   `lookup_*` tools," steering the model toward local search. Put it in the refusals the
   agent actually sees (the `PinnedDialer` dial error, the recording proxy's error response,
   and intercept refusals of download commands), not in `offline.GuardDial`'s error, which
   only reaches operators and logs through the LLM and notification paths.

### 4.5 Reach of Offline Egress Control and Additional Implementation (Important)

For this design to satisfy its premise of "substituting knowledge offline," the offline gate,
which today applies only to platform-owned traffic, must be extended to the agent's outbound
paths. The current state and the additional implementation are as follows.

| Path | Current control | Additional implementation for offline |
| --- | --- | --- |
| LLM client dial | `offline.GuardDial` in `quotaAwareHTTPClient`; non-local proxy refused (implemented) | — |
| Notifications | `offline.GuardDial` in `blockInternalDial` (implemented) | — |
| Model-list fetch | Local-only policy in `modelURLGuard` (implemented) | — |
| Update check | Forced off (implemented) | — |
| WebFetch / enrich probes / custom HTTP tool | `intercept.PinnedDialer`: scope-confined only while the target gate is on; gate off or unscoped client → any address | When offline and the gate is off (or there is no scope), refuse addresses outside `offline.IsLocalIP` plus an operator allow-list of CIDRs. With the gate on, keep the scope as the authority (see note) |
| Bash traffic through the recording proxy (`traffic`; `HTTP(S)_PROXY` / `ALL_PROXY`) | Upstream dial via `PinnedDialer` (unscoped) | Same rule at the proxy's upstream dial. Catches proxy-honoring tools only; not a security boundary |
| **Bash direct connections** (tools ignoring the proxy variables, raw sockets) | None | **Not possible with Go dial hooks**. Block with network isolation at the container/OS level; see the Docker sandbox layer in the [offline toolbox design](offline-toolbox.md) §6.4 |
| `mcphttp` (external MCP) | No gate | Refuse non-local MCP with `offline.CheckEndpointLocal` when a server is registered or started, and dial with `offline.GuardDial` (DNS rebinding) |
| `web_search` tool (ddgs / Brave / Tavily / Keenable / DeepSeek) | Opt-in setting | Forced off while offline; turning it on is refused (found during implementation) |
| Global egress proxy setting | Any proxy accepted | Must be local while offline; a saved non-local proxy is ignored at startup (found during implementation) |
| Archive store (S3) | Any HTTPS endpoint | Must be local (e.g. MinIO) while offline + `GuardDial` dialer (found during implementation) |
| Embedding endpoint (new) | — | `CheckEndpointLocal` when the profile is saved + a `GuardDial` dialer, same as the LLM client |

**Implementation status (2026-11-27)**: every row above is implemented and covered by tests,
including the embedding endpoint (Phase 2, see §8):

- `offline/egress.go`: `ARTEX_OFFLINE_ALLOW_CIDRS` and name resolution with filtering.
- `intercept/offline_dial.go`: code `OFFLINE_EGRESS_BLOCKED`.
- `traffic/offline.go`: a readable 403 for plain and intercepted requests, and a refusal at
  dial time for tunnels.
- Gates in `mcphttp`, `archivestore`, and the server's proxy and web-search settings.
- The embedding client (`knowledge/embed.go`) dials through `offline.GuardDial` and refuses a
  non-local endpoint with `CheckURLLocal`.

The configuration-time checks (`CheckEndpointLocal` / `CheckURLLocal`) now resolve names, so a
compose service such as `http://ollama:11434` counts as local.

> **Note (closed networks)**: Do not simply stack "local-only" on top of the scope. Closed
> networks sometimes use public address ranges internally, and an in-scope target there
> would become unreachable. With the gate on, the operator-approved scope stays the
> authority. The extra CIDR allow-list (e.g. `ARTEX_OFFLINE_ALLOW_CIDRS`) covers such ranges
> while the gate is off.

- The knowledge mechanism itself (search tools, import) has no HTTP client except the
  embedding client, which dials through `offline.GuardDial`. This keeps outbound traffic
  originating from this mechanism at zero.
- Direct Bash connections are outside the scope of this design (they are the responsibility
  of the OS/sandbox layer), but we do not claim that "the guard catches them." State clearly
  in the operational documentation as well that this is the one remaining hole that cannot be
  closed at the Go layer. Close it together with the container isolation of the sibling
  design [offline-toolbox.md](offline-toolbox.md).

## 5. Data Sources and Updates

| Source | Format | Purpose | Suggested update frequency |
| --- | --- | --- | --- |
| ExploitDB | git repo + `files_exploits.csv` | EDB search, CVE linkage | Monthly |
| NVD 2.0 snapshot (CVE / CPE / match criteria) | JSON | CVE/CPE lookup | Monthly |
| CWE | XML | CWE names for `lookup_cve` | Twice a year |
| PayloadsAllTheThings / HackTricks / WSTG | Markdown | Technique search | Quarterly |
| nuclei-templates | YAML | Template suggestions, signature-match hints | Monthly, aligned with the image (see below) |
| MITRE ATT&CK STIX | STIX 2.1 | Technique normalization (later phase) | Twice a year |

- **NVD source caveat**: The legacy NVD data feeds (`nvdcve-1.1-YYYY.json.gz`) were
  **retired** in December 2023. Pack builds use **NVD 2.0 API snapshots** (the CVE, CPE and
  CPE match criteria APIs). CVE List v5 (CVEProject git) is a useful supplement, but on its
  own it is not enough for `lookup_software`, because its records generally lack NVD's CPE
  configurations.
- **NVD enrichment gaps**: Since early 2024, a large share of new CVEs have not received NVD
  CPE/CVSS enrichment. `lookup_software` must fall back to the vendor/product/version data in
  CVE v5 `affected` entries (and CISA Vulnrichment ADP data where present) and mark such
  matches as lower confidence.
- **CPE matching**: Fingerprints (e.g. "Apache httpd 2.4.49") do not map one-to-one to CPE
  vendor/product names. Build an alias table at pack time, return several candidates rather
  than one, and evaluate version ranges (`versionStartIncluding` / `versionEndExcluding`,
  etc.) instead of comparing CPE strings.
- **ExploitDB CVE mapping is best-effort**: CVE coverage in the `codes` column of
  `files_exploits.csv` is incomplete. `lookup_cve` → EDB-ID resolution follows a "return it
  if found" approach and treats missing entries as a normal case.
- **One source for nuclei-templates**: The image already bakes in nuclei-templates for
  execution ([offline-toolbox.md](offline-toolbox.md) §2). Record the templates version in
  the pack manifest and warn at import when it differs from the image's, so that search
  results do not point at templates the local nuclei does not have.
- **Licensing**: Sources come under different licenses, some with share-alike or
  non-commercial terms. Record each source's license in the manifest and check
  redistribution terms before distributing packs outside the organization.
- **Corpus size and deltas**: The ExploitDB exploits directory + full NVD + nuclei-templates
  + HackTricks can reach several GB. Set limits/estimates for import time, disk
  (`data/knowledge/`), and index size, and use **delta packs** (§4.1) to avoid full
  re-imports.

Pack generation (`artex-knowledge build`) runs on CI or a workstation in the online
environment, performing `build` → hashing → ed25519 signing end to end. The offline side only
imports the pack (UI: System → Knowledge, or a server-side file / CLI for large packs; §4.1).

## 6. Configuration

Follow the existing conventions: deployment switches are environment variables (`ARTEX_*` in
`.env` / docker-compose), while LLM endpoints are profiles stored in the database and managed
in System → LLM. `config.json` holds only the database, `skill_dir` and `task_user_agents`, so
no `knowledge` section is added there.

| Setting | Where | Default |
| --- | --- | --- |
| `ARTEX_KNOWLEDGE` | Environment | On; `0` / `false` / `off` / `no` disables (same parsing as `ARTEX_OFFLINE`) |
| `ARTEX_KNOWLEDGE_DIR` | Environment | `<data dir>/knowledge` |
| `ARTEX_KNOWLEDGE_MAX_CHUNKS` | Environment | 8 (chunks per search) |
| `ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES` | Environment | 4096 |
| `ARTEX_OFFLINE_ALLOW_CIDRS` | Environment | Empty (extra ranges for the §4.5 gates) |
| Embedding profile | Database (System → LLM, new "embedding" role) | None (lexical search only) |

- **Disabled** (`ARTEX_KNOWLEDGE=0`): the tools are filtered out, the system-prompt line is
  omitted, and no index queries run. Pack files and tables are kept, so re-enabling needs no
  re-import.
- The embedding profile goes through the same `ValidateOffline` / `CheckEndpointLocal` check as
  LLM profiles. In Docker, the endpoint for Ollama on the host is
  `http://host.docker.internal:11434` (`127.0.0.1` is the container itself), as in the
  existing `ARTEX_LLM_PRIVATE_ENDPOINTS` example.

## 7. Security Considerations

- **Packs are a trust boundary** — Signature first, then per-file hashes during a safe,
  staged extraction (§4.1). Packs that fail any check are never activated. Corpus text reaches
  the LLM only as framed tool output (§4.3).
- **Rollback and key rotation** — Downgrades need explicit operator confirmation; signing keys
  are addressed by `key_id` so they can be rotated (§4.1).
- **Path confinement** — `read_knowledge` and `copy_knowledge_file` open paths through an
  `os.Root` on the pack directory (the same approach as the confined file tools), so `..` and
  symbolic links cannot escape it. The copy destination is confined to the run's working
  directory in the same way.
- **On-disk integrity** — Pack files are owned by the server and not writable by the executor
  uid, so an agent cannot alter the corpus that later searches return.
- **Zero outbound traffic** — Guarantee in the code structure that the knowledge mechanism
  itself uses no network (it has no HTTP client; only embedding calls go through a
  `GuardDial` dialer).
- **Resources** — Search queries have DB timeouts and row limits so they don't compete with
  the worker's turn budget. Imports run in the background with size caps, and embedding
  backfill is rate-limited.
- **Reach of egress enforcement** — The offline gates are defense in depth, not a standalone
  last line of defense (§4.5). LLM/notification traffic is already gated; WebFetch, enrich,
  the custom HTTP tool, the recording proxy and MCP are to be closed by the additional gates;
  **direct Bash traffic cannot be blocked in Go and is the responsibility of the
  OS/container layer** ([offline-toolbox.md](offline-toolbox.md)). In a true air-gapped
  environment, where there is physically no external network, these serve as layered
  insurance.

## 8. Implementation Phases

**Status (2026-11-27)**: Phase 1 is implemented (lexical search; pgvector/embeddings remain
Phase 2).

- **`knowledge` package**: the pack format and ed25519 signing (`pack.go`, `write.go`,
  `keys.go`), signature-first safe extraction (`extract.go`), the ExploitDB and NVD 2.0
  parsers (`exploitdb.go`, `nvd.go`), CPE version-range matching (`version.go`), chunking
  (`chunk.go`), the Postgres store and search/lookup queries (`store.go`, `search.go`), and
  import orchestration with staging + downgrade protection (`import.go`).
- **Migration** `db/migrations/0015_knowledge.sql`: `kb_packs` / `kb_documents` / `kb_chunks`
  / `kb_cpe_matches`, with `pg_trgm` and a generated `tsvector` + GIN indexes. pgvector is
  deliberately not here (created at runtime in Phase 2).
- **Agent tools** (`agent/knowledge_tools.go`): `search_exploits`, `lookup_cve`,
  `lookup_software`, `search_technique`, `read_knowledge` (planner + worker), and
  `copy_knowledge_file` (worker only). Added to `toolRAGCore` and the gate's no-target set;
  dropped from an agent's catalog when no pack is active.
- **Server**: the store is built at startup, an import API (`POST /api/knowledge/import`,
  `GET /api/knowledge/packs`) verifies and imports a pack, and the offline/knowledge prompt
  line points the model at the tools.
- **Builder** `cmd/artex-knowledge` (runs online): `keygen` and `build` produce a signed pack
  from ExploitDB / NVD / docs / templates directories.
- **Verified**: the non-DB core and parsers by unit tests; import + every search/lookup and
  downgrade protection by an integration test against Postgres; the agent tools by a test
  with a fake store.

**Phase 2 status (2026-11-27)**: hybrid search is implemented.

- **Embedding client** (`knowledge/embed.go`): Ollama (`/api/embed`) and OpenAI-compatible
  (`/v1/embeddings`) formats, configured by `ARTEX_KNOWLEDGE_EMBED_*`; the endpoint must be
  local in offline mode and every call dials through `offline.GuardDial`.
- **Runtime pgvector** (`knowledge/vector.go`): the extension and `kb_embeddings` (an HNSW
  cosine index) are created at runtime when pgvector is available, never in the
  checksum-locked migration; a change of embedding dimension rebuilds the table.
- **Hybrid ranking** (`knowledge/hybrid.go`): lexical (tsvector) and vector results fused
  with Reciprocal Rank Fusion. The vector index builds in the background after import (and at
  startup for an already-active pack), serialized so concurrent builds don't race; search
  stays lexical until the vectors land, and degrades to lexical if the embedder or pgvector
  is unavailable.
- **Verified**: the embedding clients and RRF fusion by unit tests; the full vector path
  (background embedding, dimension-change rebuild, and vector-only recall a lexical query
  misses) by an integration test against a `pgvector/pgvector:pg16` database.
- **Not yet**: precomputed embeddings shipped inside a pack (the "Embedding cost" note in
  §4.2). It needs the builder and importer to chunk identically; for now the background
  worker embeds against the configured local model. Tracked for a follow-up.

Phase plan:

1. **Phase 1 (done)**: ExploitDB + NVD (options A/C) — deterministic joins over CSV/JSON,
   lexical search; technique docs search too. `lookup_cve` / `search_exploits` /
   `lookup_software` / `search_technique` / `read_knowledge` / `copy_knowledge_file`. Pack
   signature verification and safe import (option H). The offline gates of §4.5 shipped
   earlier.
   Technique-document search (option B, lexical) and import from a server-side file / CLI
   landed in Phase 1 too.
2. **Phase 2 (done)**: Hybrid search with pgvector + a local embedding model (option G): the
   runtime-created vector table, background embedding, and RRF fusion. Precomputed
   embeddings shipped in a pack remain for a follow-up (see the status note above).
3. **Phase 3**: nuclei-templates (option D) with version alignment against the image; delta
   packs; precomputed in-pack embeddings.
4. **Phase 4**: ATT&CK STIX (option E), EPSS/KEV snapshots, and integrated tags with skills.

## Revision Notes (2026-11-27)

Review against the code on branch `feat/offline-local-llm-only`:

- Corrected the reach of the current offline mode: update checks are forced off and the
  model-list fetch has its own guard (neither uses `GuardDial`). `PinnedDialer` confines
  WebFetch/enrich only while the target gate is on. `hardening` / `intercept` / `traffic` are
  not OS-level network controls.
- Added missing egress paths: the custom HTTP tool, Bash traffic through the recording proxy,
  and the embedding endpoint.
- `toolRAGCore` takes exact names; a `search_*` pattern would also match existing tools.
- pgvector cannot go into the checksum-locked migrations; vector storage is now created at
  runtime. Noted the image switch (same major version, Alpine → Debian collation) and
  external-DSN privileges.
- Postgres ranking is not BM25; terminology fixed.
- Agents cannot read `data/knowledge/` (confined file tools, executor uid); added
  `copy_knowledge_file`.
- Pack import: signature-first verification, safe tar extraction, staging, rollback
  protection, key rotation, large-pack import paths. Moved pack signing to Phase 1.
- Data sources: NVD 2.0 / enrichment-gap handling, CPE version-range matching,
  nuclei-templates version alignment, licensing.
- Configuration now follows the project's conventions (environment variables + DB profiles
  instead of a `config.json` section); fixed the in-container Ollama URL.
