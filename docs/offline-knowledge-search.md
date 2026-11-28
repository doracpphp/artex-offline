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
| E. MITRE ATT&CK STIX | Technique lookup from Enterprise/ICS/Mobile STIX bundles | **Adopted (Phase 4)** | Normalizes technique tags and pivots findings to local exploits/templates |
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
│  ├ PayloadsAllTheThings  │                  │   └ data/knowledge/packs/<id>/<ver>/   │
│  ├ HackTricks, WSTG      │                  │  agent tools:                          │
│  ├ nuclei-templates      │                  │   search_exploits / lookup_cve         │
│  └ ATT&CK STIX           │                  │   lookup_technique / lookup_software   │
└──────────────────────────┘                  │   search_technique / read_knowledge    │
                                              │   copy_knowledge_file                  │
                                              │  egress gates = defense in depth (4.5) │
                                              └────────────────────────────────────────┘
```

### 4.1 Knowledge Packs

A single tar.gz archive (`knowledge-pack-<ver>.tar.gz`):

```
manifest.json          # format, kind, pack id, version, base version (delta packs only),
                       # build time, sources (upstream version + license), signing key id,
                       # path / size / SHA-256 of every file, deletions (delta packs only),
                       # embedding sets (model, dimension, chunk size, count, digest)
manifest.sig           # ed25519 signature over manifest.json
exploitdb/             # files_exploits.csv + exploits directory (actual files)
nvd/                   # NVD 2.0 API snapshot (CVE, CPE, match criteria)
docs/                  # technique documents (PayloadsAllTheThings, HackTricks, WSTG …)
templates/             # nuclei-templates, in the repository's (and the image's) layout
attack/                # MITRE ATT&CK STIX 2.1 bundles (enterprise / ics / mobile)
embeddings/            # optional: precomputed chunk vectors, <model>-<version>.akv
```

CWE names (the CWE dictionary) are not shipped yet: `lookup_cve` returns CWE ids only.

- **Verification order**: Verify `manifest.sig` on the **raw manifest bytes** against the
  trusted keys **before parsing them** (`knowledge.VerifyRaw`): only bytes a trusted key
  signed are parsed, and the manifest's `key_id` must then name the key that actually
  verified it. `format` (currently `1`) and `kind` (`"knowledge"`) are mandatory, so a
  validly signed manifest of another kind or a newer format is refused rather than misread.
  `pack_id`, `version` and `key_id` must be 1-64 characters from `A-Z a-z 0-9 . _ + -`
  starting with a letter or digit (they become directory names). Then stream the archive
  entries, accept only paths listed in the manifest, and check each file's size and SHA-256
  as it is written. Reject the pack if a listed file is missing or an unlisted file is
  present. The pack is a trust boundary (§7).
- **Safe extraction**: Accept regular files and directories only. Reject symbolic links,
  hard links, device files, absolute paths and `..` components. Cap the total extracted size
  and file count (decompression bombs) and check free disk space before starting.
- **Staging and activation** (`knowledge/import.go`): imports are serialized (a second one
  gets `409`). Each import extracts into a fresh staging directory, indexes into an
  uncommitted transaction, renames the staging directory to a new versioned name
  (`data/knowledge/packs/<pack-id>/<version>-<manifest-hash>-<n>/`) that nothing references
  yet, and then commits — activating the new `kb_packs` row, deactivating the old one and
  recording the key pin in one transaction. Only after the commit are the superseded
  directories and the superseded versions' index rows removed. A failed or interrupted
  import therefore leaves the active pack's rows and files untouched.
- **Signing key**: **Embedding the ed25519 public key in the binary is recommended** (config
  is mutable, so an attacker who gains write access could swap out the key along with it).
  Embed a small key set addressed by `key_id`, so that a key can be rotated by shipping a new
  binary without invalidating packs signed with the previous key. `ARTEX_KNOWLEDGE_PUBKEY`
  (with `ARTEX_KNOWLEDGE_KEY_ID`) can **add** a key, never replace an embedded one (an env key
  under an embedded id is refused). On top of that, the first import of a pack id **pins**
  the signing key's fingerprint (`kb_key_pins`, TOFU): a later pack of that id signed by any
  other key is refused until the operator re-imports with `?repin=1`. The trusted keys and
  their SHA-256 fingerprints are printed at startup and returned by
  `GET /api/knowledge/packs` (with each pack's verifying key and the pins), so the
  fingerprint can be compared out of band.
- **Rollback protection**: A validly signed old pack is still stale, and may be known-bad.
  Refuse a pack whose version is lower than the active pack with the same id unless the
  operator explicitly confirms the downgrade.
- **Delta packs** (`knowledge/delta.go`): a delta carries `base_version`, the added and
  changed files and a deletion list, and applies only on top of the active pack of the same
  id at exactly that version (anything else is refused, as is a deletion of a file the base
  does not have). The importer builds the new version's directory from the base directory
  — hard links, so unchanged files cost no copy; each is checked against the size its
  manifest records — plus the delta's verified files, and indexes the merged set exactly as
  it would a full pack. The builder makes a delta with `build -base PREVIOUS-FULL.tar.gz
  -delta-out DELTA.tar.gz` (it also writes the full pack, which the next delta is built
  against). Deltas chain: a delta against the full pack of version N applies to an N that
  was itself imported as a delta, because both describe the same files.
- **Storage**: Actual files are extracted under `data/knowledge/packs/<pack-id>/<version
  dir>/`, owned by the server; the directories are created `0750`, so the executor uid that
  agent processes run as can neither write nor read them (agents read pack content through
  the tools). Postgres holds only the search index and metadata. File paths are always
  confined under the active version's directory. Each version directory also keeps the
  manifest it was indexed from as `manifest.json` — the signed one for a full pack, the
  merged one for a delta — whose SHA-256 is `kb_packs.manifest_sha256`, so a later delta
  can trust the base manifest it reads back.
- **Import entry points**: there is **no UI yet**. `POST /api/knowledge/import` takes either
  `?path=` — a file inside the knowledge directory, e.g. `inbox/pack.tar.gz` (anything
  outside it is refused) — or the pack as a streamed request body, written to the inbox
  rather than buffered. Packs can reach several GB (§5), so the server-side file is the
  recommended route. The import runs synchronously (capped at 30 minutes). Both routes
  share the same verification path.

### 4.2 Search Index (Postgres)

| Table | Role |
| --- | --- |
| `kb_packs` | Pack management (pack id, version, key id and fingerprint, manifest hash, files directory, import timestamp, active flag) |
| `kb_key_pins` | The signing key each pack id is pinned to (TOFU; §4.1) |
| `kb_documents` | One row per CVE, exploit, doc, template or ATT&CK technique in a pack (pack row, kind `cve` / `exploit` / `doc` / `template` / `technique`, ext_id such as the CVE id, EDB-ID or technique id, source_path, title, cve_ids, cpe_tags, technique_ids, and a `meta` jsonb with the structured fields: CVSS/CWE/references for a CVE; type/platform/date/port/author/verified for an exploit; tactics/platforms/data_sources for a technique) |
| `kb_chunks` | Body chunks + a generated `tsvector` column (GIN index); a trigram index for the substring fallback is created at runtime when `pg_trgm` is available |
| `kb_cpe_matches` | One row per CVE applicability criterion (vendor, product, CPE criteria, vulnerable flag, version-range bounds) for `lookup_software` |
| `kb_embeddings` | Chunk embeddings (chunk_id, model, `vector(N)`); **created at runtime** only when pgvector is available (see below). The dimension N is the column's, fixed per table |

`technique_ids` (added in migration 0016) lists the ATT&CK technique ids a cve / exploit /
doc / template relates to, the way `cve_ids` links documents to CVEs; a GIN index backs the
join from a technique to the documents tagged with it.

> **Premise**: `db/` makes no use of full-text search today, so the FTS foundation is
> **entirely new**. Postgres itself is already a dependency. The schema goes into a numbered
> migration (`db/migrations/NNNN_knowledge.sql`), which `db.Open` applies once and then
> locks by checksum.
>
> - **No extension is created by the migration.** `pg_trgm` ships in the stock
>   `postgres:16-alpine` image, but an external database's role may lack the right to
>   create extensions, and a migration that fails blocks startup. So the knowledge package
>   creates `pg_trgm` and its two trigram indexes at startup, best effort
>   (`Store.EnsureTrigramIndexes`); without them search works the same, only the substring
>   fallback scans sequentially, and the startup log says so.
> - **pgvector is not shipped either, and must not go in that migration.** On the stock image the
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
>   allowed to create extensions; the feature then runs lexical-only and says so in the
>   startup log (there is no knowledge UI yet).

- **Lexical search**: every chunk (CVE, exploit, doc, template) has a generated `tsvector`
  in the `english` configuration with a GIN index; the query goes through
  `websearch_to_tsquery('english', …)` and results are ranked with `ts_rank_cd`. Identifiers
  that the English parser splits or stems (`CVE-2021-41773`, `wp-config.php`, function
  names, payload symbols) are caught by a case-insensitive substring match (`ILIKE`) OR-ed
  into the same query, which the trigram index speeds up when `pg_trgm` is present. There
  is no separate `simple`-configuration index and no query preprocessing beyond what
  `websearch_to_tsquery` does.
- **Vector**: pgvector (HNSW, cosine distance). The embedding model is configured with
  environment variables, not an LLM profile: `ARTEX_KNOWLEDGE_EMBED_PROVIDER` (`ollama` for
  `/api/embed`, or `openai` for `/v1/embeddings`), `ARTEX_KNOWLEDGE_EMBED_MODEL` (e.g.
  `nomic-embed-text`, `bge-m3`) and `ARTEX_KNOWLEDGE_EMBED_ENDPOINT` (`knowledge/embed.go`).
  It is a *separate* endpoint from the chat LLM: a chat-only local gateway (e.g. Strata,
  which serves chat/completions and Anthropic messages but no embeddings) cannot provide the
  vectors, so a deployment that uses such a gateway for the LLM runs a dedicated local
  embedder (Ollama) for the vector half, or stays lexical-only. The endpoint must be local in
  offline mode (`offline.CheckURLLocal`) and every call dials through `offline.GuardDial`,
  like the LLM client (§4.5). Each row records the model that made it, and search uses only
  the current model's rows. A changed model drops the stale vectors and re-embeds; a changed
  dimension rebuilds the table (the column dimension is fixed). An embedder that returns
  vectors of the wrong dimension stops the background worker with an error. Common models
  (768 / 1024 dimensions) fit within pgvector's 2,000-dimension HNSW limit.
- **Embedding cost**: Embedding a multi-GB corpus on a local server can take hours and
  competes with the chat model for the GPU. Today the chunks of the active pack are embedded
  in the background after import (and at startup, resuming where it stopped), 64 chunks per
  request, one worker at a time but without rate limiting; lexical search answers in the
  meantime. Each search also needs one query embedding, bounded at 15 seconds before search
  falls back to lexical. Two things keep this cost down (`knowledge/embedfile.go`):
  - **Precomputed vectors in the pack**: `build -embed-model … -embed-endpoint …` embeds the
    chunks online and ships them under `embeddings/`, declared in the manifest (model,
    dimension, chunk size, count, optional digest) and covered by its hashes like any file.
    A vector is keyed by the SHA-256 of the exact chunk text, which builder and importer
    produce with the same code, so a set is used only when its model name **and** chunk size
    equal the configured `ARTEX_KNOWLEDGE_EMBED_MODEL` and `ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES`;
    otherwise it is ignored and the worker embeds locally. The digest is recorded for
    information and not compared. With `-base`, the builder reuses the previous full
    pack's vectors for unchanged chunks, and a delta ships only the new ones.
  - **Reuse across updates**: right after a new version is activated, the current model's
    vectors of the previous version's chunks are copied to the new chunks with the same
    text, before the old rows are removed. An update — full or delta — therefore re-embeds
    only what changed.
- **Fusion**: Take the lexical and the vector top 4N and merge them with RRF (Reciprocal Rank
  Fusion, k = 60), returning the top N (`knowledge/hybrid.go`). Without the vector path —
  no embedder, no pgvector, no vectors of the current model yet, or a failed query
  embedding — return the lexical ranking as is.

### 4.3 Agent Tools (toolcatalog Additions)

| Tool | Input | Behavior |
| --- | --- | --- |
| `search_exploits` | Query, optional exploit type and platform | Hybrid search over the ExploitDB entries (CSV metadata + exploit file bodies). Returns EDB-ID, title, type, platform, date, verified flag, CVEs, path (when the pack carries the file), a snippet and the source |
| `lookup_cve` | CVE ID | Returns the description, CVSS, CWEs and references from the NVD mirror, the ExploitDB entries that reference the CVE, the nuclei templates whose classification names it (id, name, severity, pack path, and `local_path` when this installation has the file, to run with `nuclei -t`), and the ATT&CK techniques its templates map to (id + name; follow with `lookup_technique`). A CVE known only from an exploit or a template is still returned. Affected products are not listed (use `lookup_software` in the other direction) |
| `lookup_software` | Product name, optional vendor and version | Folds the product to CPE form (lower case, spaces to underscores), prefers CVEs whose CPE product matches exactly and falls back to a literal substring match only when there is none, evaluates the NVD version ranges in Go, and returns one hit per CVE with the matched CPE, vendor, product, `match_basis` (`exact` / `partial`) and whether a version was checked — not a numeric confidence |
| `search_technique` | Query (technique, payload, WAF evasion, etc.) | Hybrid search over the pack's `docs/` and `templates/` files. Returns kind (`doc` / `template`), title, path, chunk number, a snippet and the source; a nuclei template hit adds its template id, severity and `local_path` |
| `lookup_technique` | ATT&CK technique id (T1190, T1059.001; a token like `attack.t1190` is normalised) | Returns the technique's name, tactics, platforms, data sources and description from the local ATT&CK mirror, plus the exploits, nuclei templates and CVEs tagged with it (a template with `local_path` when the installation has the file). A technique known only from a tag (no ATT&CK bundle imported) still returns its related documents |
| `read_knowledge` | document id (EDB-ID, CVE id) or source path, plus a 1-based chunk number | Returns the full text of one chunk (capped at `ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES`) and the document's chunk count; read further chunks with further calls. Progressive disclosure: search → read |
| `copy_knowledge_file` | document id / source path, optional destination name | Copies the file (an exploit source, a doc or a template) into the run's working directory so that Bash and the file tools can use it; regular files up to 32 MiB |

Binding: the tools are part of the planner's and the worker's built-in tool sets
(`PlannerTools` / `WorkerTools`), and so enter the tool catalog as seeds bound to those
agents (`BuiltinToolSeeds`). `search_*` / `lookup_*` / `read_knowledge` are bound to **both
`planner` and `worker`** (knowledge serves action and is needed in both the planning and
execution phases); `copy_knowledge_file` to `worker` only, since the planner has no shell
or file tools. In System → Tools an operator can unbind them from those two agents, but
**cannot add them to another agent**: ToolResolve only filters an agent's built-in set, and
the main agent (chat), goals, auto and pentest agents do not carry these tools, so checking
them there has no effect. Offering them to the main agent would need the tools added to its
built-in set and its prompt switched to `offlineBlock(true)`, which adds the knowledge
line (today only the planner and worker prompts carry it). When
knowledge search is disabled (`ARTEX_KNOWLEDGE=0`) or no pack is active, the tools are
filtered out when tools are resolved, instead of answering "no data" on every call.

Why `copy_knowledge_file` is needed: the agent's file tools are confined to the run's working
directory (`os.Root`, `agent/filetools.go`), and Bash runs as the unprivileged executor, which
cannot read the `0750` pack directories, so neither can reach the pack files. Copying is the only path from a pack to execution, and
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
- **Limits** — Cap the number of results and bytes per response to protect the context
  budget: `ARTEX_KNOWLEDGE_MAX_CHUNKS` (default 8) results per search and
  `ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES` (default 4096) per chunk; `lookup_software` returns at
  most 50 CVEs.

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
| LLM client dial | `offline.GuardDial` in `quotaAwareHTTPClient`; any LLM proxy refused while offline (implemented) | — |
| Notifications | `offline.GuardDial` in `blockInternalDial`, on top of the existing guard: loopback still needs `ARTEX_NOTIFY_ALLOW_LOCAL`, link-local / metadata stay blocked (implemented) | — |
| Model-list fetch | Local-only policy in `modelURLGuard` (implemented) | — |
| Update check | Forced off (implemented) | — |
| WebFetch / enrich probes / custom HTTP tool / SOCKS5 and transparent relays | `intercept.PinnedDialer` | While offline, **every** dial — gate off, unscoped, or gated — reaches only `offline.AllowedAddr` addresses (local + `ARTEX_OFFLINE_ALLOW_CIDRS`, never metadata). A gated scope, including derived exemptions, can only narrow this (see note) |
| Bash traffic through the recording proxy (`traffic`; `HTTP(S)_PROXY` / `ALL_PROXY`, only while traffic capture is on) | go-mitmproxy dials the name itself | Refused unless **every** address the name resolves to is allowed; any upstream proxy refused. Catches proxy-honoring tools only; not a security boundary |
| **Bash direct connections** (tools ignoring the proxy variables, raw sockets), custom command tools, local MCP servers started over stdio | None in Go | **Not possible with Go dial hooks**. Stopped by the in-container egress firewall, on by default in the compose files ([offline-toolbox.md](offline-toolbox.md) §6.4) |
| Browser MCP / other sidecar containers | None in Go | Outside the ARTEX container's network namespace, so **not** covered by its firewall: run them on an internal network or firewall them at the host |
| DNS lookups | None | **Residual channel**: the firewall stops connections, not name resolution, which Docker's resolver forwards from the host. Block outbound DNS at the host/network edge for a hard air gap |
| `mcphttp` (external MCP) | No gate | Refuse non-local MCP with `offline.CheckEndpointLocal` when a server is registered or started, and dial with `offline.GuardDial` (DNS rebinding) |
| `web_search` tool (ddgs / Brave / Tavily / Keenable / DeepSeek) | Opt-in setting | Forced off while offline; turning it on is refused (found during implementation) |
| Global egress proxy setting and the custom HTTP tool's own proxy | Any proxy accepted | Refused while offline, **local ones included** — a proxy forwards to any destination; a saved global proxy is ignored at startup |
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

> **Note (closed networks, single authority)**: closed networks sometimes use public address
> ranges internally. Those ranges go in `ARTEX_OFFLINE_ALLOW_CIDRS`, which is the **single
> authority** for non-local reach in offline mode: every Go gate and the egress firewall
> apply the same set, and an operator-approved target scope can only narrow it. (An earlier
> draft kept the scope as the authority while the gate was on; that let an approval — or a
> derived exemption such as a stale cloud LLM profile URL — open a route the firewall would
> then silently drop, so the two layers disagreed.)

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
| MITRE ATT&CK STIX | STIX 2.1 | Technique normalization (`lookup_technique`, technique tags) | Twice a year |

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
  execution ([offline-toolbox.md](offline-toolbox.md) §2). The pack's `templates/` keeps
  the repository layout, which is also the image's (`/opt/nuclei-templates`,
  `NUCLEI_TEMPLATES_DIR`), so `templates/<rel>` is `<NUCLEI_TEMPLATES_DIR>/<rel>` locally.
  The builder records the release tag (`-templates-version`) as the `nuclei-templates`
  source version; the importer compares it with the image's (from the build-time tool
  inventory) and returns a warning when they differ, when the pack does not record it, or
  when the installation has no baked templates. Independently of the version, a hit carries
  `local_path` only when that exact file exists locally, so it never names a template the
  local nuclei cannot open (a revision difference within the same path is what the warning
  is for). Templates are parsed (`knowledge/nuclei.go`): id, name, severity, tags, CVE and
  CWE classification, vendor/product; other files under `templates/` are indexed as text.
- **Licensing**: Sources come under different licenses, some with share-alike or
  non-commercial terms. Record each source's license in the manifest and check
  redistribution terms before distributing packs outside the organization.
- **Corpus size and deltas**: The ExploitDB exploits directory + full NVD + nuclei-templates
  + HackTricks can reach several GB. Set limits/estimates for import time, disk
  (`data/knowledge/`), and index size, and use **delta packs** (§4.1) to avoid full
  re-imports.

Pack generation (`artex-knowledge build`) runs on CI or a workstation in the online
environment, performing `build` → hashing → ed25519 signing end to end. The offline side only
imports the pack (`POST /api/knowledge/import` with a server-side file or a streamed body; §4.1).

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
| `ARTEX_OFFLINE_ALLOW_CIDRS` | Environment | Empty (extra ranges for the §4.5 gates and the firewall) |
| `ARTEX_KNOWLEDGE_PUBKEY` / `ARTEX_KNOWLEDGE_KEY_ID` | Environment | None; adds one trusted signing key (never replaces an embedded one) |
| `ARTEX_KNOWLEDGE_EMBED_PROVIDER` / `_MODEL` / `_ENDPOINT` | Environment | None (lexical search only); `ollama` or `openai` format |
| `NUCLEI_TEMPLATES_DIR` | Environment (the image sets it) | `/opt/nuclei-templates` in the image; where template hits look for `local_path` |

- **Disabled** (`ARTEX_KNOWLEDGE=0`): the tools are filtered out, the system-prompt line is
  omitted, and no index queries run. Pack files and tables are kept, so re-enabling needs no
  re-import.
- The embedding endpoint is checked with `offline.CheckURLLocal` at startup and every call
  dials through `offline.GuardDial`. In Docker, the endpoint for Ollama on the host is
  `http://host.docker.internal:11434` (`127.0.0.1` is the container itself). Changing the
  embedding model drops the stored vectors and rebuilds them in the background.

## 7. Security Considerations

- **Packs are a trust boundary** — Signature first, then per-file hashes during a safe,
  staged extraction (§4.1). Packs that fail any check are never activated. Corpus text reaches
  the LLM only as framed tool output (§4.3).
- **Rollback and key rotation** — Downgrades need explicit operator confirmation; signing keys
  are addressed by `key_id` so they can be rotated, and a pack id's key change needs an
  explicit re-pin (§4.1).
- **Path confinement** — `read_knowledge` reads chunks from the index, not files.
  `copy_knowledge_file` opens the file through an `os.Root` on the active version's
  directory (whose stored name is re-validated), so `..` and symbolic links cannot escape
  it; only regular files up to 32 MiB are copied. The copy destination is confined to the
  run's working directory in the same way.
- **Dirty data** — Pack data is signed, not clean: invalid UTF-8 is replaced, NUL bytes are
  removed (Postgres TEXT/jsonb refuse them), and a file with a NUL in its first 8 KiB is
  treated as binary and indexed on its metadata only. One bad row does not abort an import.
- **On-disk integrity** — Pack files are owned by the server and not writable by the executor
  uid, so an agent cannot alter the corpus that later searches return.
- **Zero outbound traffic** — Guarantee in the code structure that the knowledge mechanism
  itself uses no network (it has no HTTP client; only embedding calls go through a
  `GuardDial` dialer).
- **Resources** — Search queries have row limits, and a query embedding times out after 15
  seconds (search then falls back to lexical). There is no per-query statement timeout yet.
  Imports run synchronously, one at a time, with size and file-count caps (8 GiB / 200,000
  files) and a 30-minute limit. Embedding backfill runs in the background in batches of 64
  chunks, serialized but not rate-limited.
- **Reach of egress enforcement** — The offline gates are defense in depth, not a standalone
  last line of defense (§4.5). Every outbound path ARTEX itself makes is gated; **direct Bash
  traffic cannot be blocked in Go** and is stopped by the in-container egress firewall, on by
  default with docker compose ([offline-toolbox.md](offline-toolbox.md) §6.4). DNS and relays
  on allowed ranges remain residual channels. In a true air-gapped environment, where there
  is physically no external network, these serve as layered insurance.

## 8. Implementation Phases

**Status (2026-11-27)**: Phase 1 is implemented (lexical search; pgvector/embeddings remain
Phase 2).

- **`knowledge` package**: the pack format and ed25519 signing (`pack.go`, `write.go`,
  `keys.go`), signature-first safe extraction (`extract.go`), the ExploitDB and NVD 2.0
  parsers (`exploitdb.go`, `nvd.go`), CPE version-range matching (`version.go`), chunking
  (`chunk.go`), the Postgres store and search/lookup queries (`store.go`, `search.go`), and
  import orchestration with versioned activation, key pinning and downgrade protection
  (`import.go`).
- **Migration** `db/migrations/0015_knowledge.sql`: `kb_packs` / `kb_key_pins` /
  `kb_documents` / `kb_chunks` / `kb_cpe_matches` with a generated `tsvector` + GIN index.
  It creates no extension, so a role without `CREATE EXTENSION` rights can apply it;
  `pg_trgm` (trigram indexes) and pgvector are created at runtime, best effort.
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
- Precomputed embeddings shipped inside a pack arrived with Phase 3 (below).

**Phase 3 status (2026-11-28)**: implemented.

- **nuclei-templates** (option D, `knowledge/nuclei.go`): templates are parsed and
  indexed with their id, CVEs, severity and tags; `lookup_cve` links them and
  `search_technique` returns them, both with `local_path` when the installation has the
  file; the templates version is compared with the image's at import (§5).
- **Delta packs** (`knowledge/delta.go`, §4.1): accepted on top of exactly their base,
  merged with hard links and indexed like a full pack; `build -base … -delta-out …` makes
  them.
- **Precomputed in-pack embeddings** and **reuse across updates**
  (`knowledge/embedfile.go`, §4.2).
- **Verified**: unit tests for template parsing, the vector file format, the builder's
  vector reuse, delta computation and merge, and the version warning; Postgres integration
  tests (`postgres:16-alpine` and `pgvector/pgvector:pg16`) for template links and local
  paths, delta import including a chained delta and the refusals (no base, wrong base,
  tampered stored manifest), precomputed vectors used without calling the model (and
  ignored for another model), and vectors reused after an update; a CLI test for
  `build -base -delta-out`.

Phase plan:

1. **Phase 1 (done)**: ExploitDB + NVD (options A/C) — deterministic joins over CSV/JSON,
   lexical search; technique docs search too. `lookup_cve` / `search_exploits` /
   `lookup_software` / `search_technique` / `read_knowledge` / `copy_knowledge_file`. Pack
   signature verification and safe import (option H). The offline gates of §4.5 shipped
   earlier.
   Technique-document search (option B, lexical) and import from a server-side file / CLI
   landed in Phase 1 too.
2. **Phase 2 (done)**: Hybrid search with pgvector + a local embedding model (option G): the
   runtime-created vector table, background embedding, and RRF fusion.
3. **Phase 3 (done)**: nuclei-templates (option D) with version alignment against the image;
   delta packs; precomputed in-pack embeddings, plus vector reuse across updates. MSF module
   metadata (the other half of option D) is not included.
4. **Phase 4 (in progress)**: ATT&CK STIX (option E) **done**; EPSS/KEV snapshots and skill
   tags remain.

**Phase 4 status (2026-11-28)**: ATT&CK is implemented.

- **STIX parser** (`knowledge/attack.go`): `attack/*.json` bundles (enterprise / ics /
  mobile) are parsed into `technique` documents — id (T####, T####.###), name, tactics,
  platforms, data sources, detection; revoked and deprecated techniques are skipped, and a
  sub-technique tags its parent so a lookup of the parent reaches it.
- **Technique tags** (migration `0016_knowledge_attack.sql`): `technique_ids` on every
  document; nuclei templates contribute ATT&CK ids found in their tags
  (`NormalizeTechniqueID` accepts `T1190`, `t1190`, `attack.t1059.001`).
- **`lookup_technique`** (`knowledge/search.go`, `agent/knowledge_tools.go`): resolves a
  technique and returns the local documents tagged with it; `lookup_cve` surfaces the
  techniques its templates map to.
- **Builder**: `build -attack DIR -attack-version TAG`.
- **Verified**: unit tests for the STIX parser, id normalisation and template tag extraction;
  Postgres integration tests (`postgres:16-alpine`, `pgvector/pgvector:pg16`) for technique
  import, `lookup_technique` and the CVE↔technique links; a CLI test for `-attack`; the
  0016 migration is covered by the migrate test and verified to apply on top of 0015.
- **Not yet**: EPSS/KEV snapshots and skill-to-technique tags (the rest of Phase 4), and the
  CWE dictionary (`lookup_cve` returns CWE ids only).

**Review follow-up (2026-11-27)**: a code, security and design review of the first
implementation led to these changes, each covered by tests (the Postgres ones against
`postgres:16-alpine`, `pgvector/pgvector:pg16` and a role without `CREATE EXTENSION`):

- `pack_id` / `version` / `key_id` syntax enforced (a `pack_id` of `..` or `../../keys`
  could previously reach outside the knowledge directory on import and on copy).
- ExploitDB file paths: the CSV's `file` column is relative to the ExploitDB root, so exploit
  bodies are read from `exploitdb/<file>` (they were not indexed or copyable before).
- Dirty data no longer aborts an import (invalid UTF-8, NUL, binary exploit files); the
  builder skips `.git` and other hidden entries and takes only text files for `docs/`.
- Atomic, versioned activation with an import lock (§4.1).
- Signature verified before parsing; `format` and `kind` mandatory; delta fields refused;
  env keys add-only; key pinning with explicit re-pin; fingerprints in the pack list.
- `lookup_software`: exact product first, literal `LIKE`, a fixed row order and a
  `match_basis` per hit.
- Embedding: a model change rebuilds the vectors; an embedder returning vectors of the wrong
  dimension stops the worker instead of looping.
- `pg_trgm` moved out of the migration (runtime, best effort).

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
