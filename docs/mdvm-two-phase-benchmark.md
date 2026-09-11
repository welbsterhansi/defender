# MDVM two-phase batched scan — architecture + benchmark

## Motivation (baseline empírico 2026-09-11)

Full-ACR scan (`bdsoregistry`, 9389 unique digests) run with `--skip-tags`:

- **Phase 2 (per-digest with JOIN)**: 145 digests em ~15 min = ~9.7 digests/min
- **Projected total**: ~16h para os 9389 digests
- Digests com `rows=0` também levavam ~4-5s → **prova de custo fixo por chamada**
- Cada `az rest` per-digest pagava o custo integral de tocar `microsoft.security/cvedetails` no motor ARG, independente do volume retornado do lado de `assessments`

`show-tags` **não** era o gargalo (Fase 1 foi pulada via `--skip-tags` e Fase 2 continuou lenta com mesmo padrão de latência). Documentado como suspeito descartado em `erros.md`.

## Design

Substituir o loop per-digest com JOIN inline por **duas queries batched** + merge local:

```
PHASE 0    enumerate  (unchanged)         → DIGEST_PAIRS[]
PHASE 1    tag_resolve (unchanged)        → TAG_CACHE
PHASE 2a   batched assessments  (no JOIN) → assessments.jsonl
PHASE 2b   extract unique CVE IDs         → unique_cves.txt
PHASE 2c   batched cvedetails             → cvedetails.jsonl
PHASE 2d   Python merge + filter          → vulnerable_images_report.csv
```

### Query A — `build_batched_assessments_query <digest1> <digest2> ...`

- `| where _digest in (<batch>)` filtra cedo.
- **Sem** `join` com cvedetails.
- Projeta 14 campos base + 6 `inline*` (fallback quando enrichment falha).
- Batch size default: 50 digests.

### Query B — `build_batched_cvedetails_query <cve1> <cve2> ...`

- Só `microsoft.security/cvedetails`.
- Filtra `status != Reject`.
- `| where cveIdJoin in (<batch>)` (uppercase pra normalização case-insensitive).
- Retorna 6 campos enriched (cvssScore, publishedDate, severity, 3 exploit flags).
- Batch size default: 500 CVE IDs.

### Local merge — `enrich_cvedetails.py`

- Lê `assessments.jsonl` + `cvedetails.jsonl` + `tags.tsv`.
- Dict lookup por `toupper(cveId)`.
- Coalesce: enrichment → inline → severity-derived (para CVSS).
- Aplica `--min-score`/`--max-score` **após** enrichment.
- Emite CSV com 19 colunas na ordem exata do contrato, quoting compatível com `csv_field` do bash.

## Fallback controlado (não paralelismo!)

`_scan_batch_recursive` divide batch pela metade quando `UnexpectedQueryExecutionError` acontece (após 3 retries do `run_arg_rest_query`):

```
100 → 50 + 50    → 25 + 25    → 12 + 13 → 6 + 6 → 3 + 3 → 1 + 1 + 1 ...
```

Se batch de 1 item ainda falhar, aborta com erro claro. **Nunca cai silenciosamente para 1-por-1** — sempre há um WARN por split e um ERROR se chegar em single-item failure.

## Modos preservados

- **report-only** (default): usa o novo path batched.
- **--block-images / --unblock**: continua no path per-digest legado (escopo naturalmente pequeno, feedback loop tighter — não faz sentido rodar batched pra 5 blocks).
- **--skip-tags**: funciona nos dois paths.
- **--scan-image**: bypassa enumerate (usa target direto).
- **--repository / --repositories**: aplicado no filtro EARLY_FILTER_B do enumerate.

## Contrato CSV preservado

19 colunas na ordem exata:
```
repository,digest,tag,cvssScore,cveId,severity,packageCategory,packageLanguage,
packageName,currentVersion,fixedVersion,patchable,remediation,fixStatus,
cveAgeDays,isInExploitKit,hasPublishedExploit,hasVerifiedExploit,
lastPushedToRegistryUTC
```

Quoting exato: `csv_field()` do bash (envolve em `"..."`, aspas internas viram `'`, newlines colapsam em espaço). `enrich_cvedetails.py` implementa o mesmo `csv_field()` em Python.

## Benchmark protocol (a rodar antes de merge pra main)

### Ambiente de teste

- ACR do cliente (`bdsoregistry`) — 9389 unique digests, 603 unique repos.
- Identidade CLI com Security Reader no tenant.
- Rodar de máquina Linux/WSL (target runtime — não macOS local).

### Runs pareados (mesmo escopo, path legado vs batched)

**Baseline (per-digest legado):**
- Roda: `./defender.sh --acr-name bdsoregistry --repository <repo-medio> --min-score 0 --max-score 10 --skip-tags`.
- Métricas: `total_arg_requests`, `total_time`, `rows_emitted`.
- Escopo sugerido: 1 repo com ~20-50 digests (rodar em 5-10 min).

**P2 batched:**
- Mesmo escopo.
- Comparar: chamadas ARG, tempo total, rows emitted (deve ser idêntico).

### Escalada

1. 1 repo pequeno (`--repository redhat-sso-7/rhsso75`, ~15 digests) → sanity check.
2. 1 repo grande (>500 digests) → validar batching + skip-token.
3. 3 repos misturados → concorrência interna do ARG.
4. 10 repos → estress mais representativo.
5. ACR inteiro (`--min-score 9.9 --max-score 10` pra CSV pequeno) → validação em escala real.

Após cada run, registrar em tabela:

| Escopo | Digests | Baseline (per-digest) | P2 (batched) | Delta chamadas | Delta tempo |
|---|---|---|---|---|---|
| 1 repo pequeno | X | Y calls / Z sec | Y' / Z' | -X% | -Y% |
| ... | | | | | |

**Não prometer** número absoluto de melhoria — é hipótese até o benchmark rodar.

## Guardrails

1. Não voltar a `subassessments`.
2. Não usar `properties.cvss["3.1"]` (schema só tem 4.0/3.0/2.0).
3. Filtrar `properties.status !~ "Reject"`.
4. Preservar todos os args, modos, formato CSV.
5. Retry/backoff [2, 5]s intacto.
6. Fallback inline `cve.*` quando cvedetails inacessível (identidade sem MG scope, CVE rejeitada).
7. Never fall silently to 1-by-1 — WARN em cada split.

## Riscos conhecidos

- **Batch size do ARG**: 50 digests / 500 CVE IDs é palpite conservador. Ajustar por benchmark.
- **Query string size limit**: `_digest in ("...", "...", ...)` pode exceder limite de tamanho em batches grandes. Mitigação: começar em 50/500 e reduzir se necessário.
- **CVE IDs unicos podem ser muitos**: se um ACR tem 50k CVE IDs únicos, precisa de 100 chamadas cvedetails (ok, ainda é ordem de magnitude menor que 9389).
- **Distinct em Python**: usa `set()` de tuplas — para scans muito grandes (>1M rows), memória pode virar problema. Não é caso atual (9389 digests × ~40 CVEs/digest = ~375k rows).

## Roadmap (não iniciar sem OK)

- P3: rewrite `defender.sh` em Python (Azure SDK `azure-mgmt-resourcegraph` + `azure-containerregistry`). Elimina subprocess overhead + libera asyncio pra paralelismo controlado (Semaphore(10) → mais 3-5x speedup).
- Se P2 já resolve o problema em prod, P3 pode aguardar.
