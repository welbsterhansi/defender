# Guia — KQL do defender.sh (ARG / Defender for Cloud)

Guia prático de como a KQL do `defender.sh` foi montada, como
descobrir campos em Azure Resource Graph (ARG), como debugar quando
um campo vem `null`/`unknown`, e como ajustar a query com segurança
quando a Microsoft muda o schema.

Público-alvo: quem vai manter o script. Assume conhecimento básico
de KQL (`where`, `project`, `extend`, `join`, `mv-expand`).

## Sumário

1. [O que a query faz](#1-o-que-a-query-faz)
2. [Arquitetura da query](#2-arquitetura-da-query)
3. [Explorando ARG do zero](#3-explorando-arg-do-zero)
4. [Descoberta de campos](#4-descoberta-de-campos)
5. [Debug — "por que este campo veio null?"](#5-debug--por-que-este-campo-veio-null)
6. [Como Microsoft "muda tudo" — casos reais](#6-como-microsoft-muda-tudo--casos-reais)
7. [Ajustando a query no código](#7-ajustando-a-query-no-código)
8. [Checklist de PR quando o schema muda](#8-checklist-de-pr-quando-o-schema-muda)

---

## 1. O que a query faz

Uma frase: **"me dá todos os CVEs de todas as imagens do ACR, com
severidade, exploitabilidade e info de fix, filtrando pelo range de
CVSS que eu quero"**.

Saída = um CSV com 18 colunas, uma linha por (imagem × pacote × CVE).

Consumido por `check_ocp.sh` que cruza com workloads OpenShift, e
por `report.py` que gera o HTML.

## 2. Arquitetura da query

### 2.1. Duas fontes, um JOIN

```
┌────────────────────────────────────────────────────────────┐
│   microsoft.security/assessments  (subscription scope)     │
│   ─────────────────────────────────────────────────────    │
│   "esta imagem tem estas CVEs neste pacote":               │
│   - repository, digest, packageName, currentVersion        │
│   - lista de CVE-ids (array em CvesDetails[])              │
│   - fixedVersion, fixStatus (por-pacote, por-CVE)          │
└────────────────────────┬───────────────────────────────────┘
                         │  toupper(cveId)
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│   microsoft.security/cvedetails  (MANAGEMENT-GROUP scope)  │
│   ─────────────────────────────────────────────────────    │
│   "o que é esta CVE, globalmente":                         │
│   - cvssScore (dict keyed "4.0"/"3.0"/"2.0")               │
│   - severity, publishedDate                                │
│   - exploitabilityDetails (IsInExploitKit, IsVerified, ...)│
│   - EPSS Score/Percentile (probabilidade de exploração)    │
└────────────────────────────────────────────────────────────┘
```

`assessments` = **cardinalidade alta**, uma linha por (imagem,
pacote). `cvedetails` = **cardinalidade baixa**, uma linha por CVE
global (compartilhada entre todos os tenants Microsoft).

### 2.2. Por que LEFT OUTER JOIN?

Se o `az login` não estiver no escopo do Management Group que expõe
`cvedetails`, o lado direito volta vazio. LEFT OUTER preserva as
linhas do `assessments` — só perdemos o enriquecimento. Melhor
degradar do que retornar 0 linhas.

### 2.3. Por que coalesce em cascata?

A Microsoft frequentemente publica o mesmo dado em 2–3 caminhos
durante transições de schema. Nosso coalesce protege contra o campo
mudar de lugar antes de a gente notar. Exemplo:

```
packageCategory = coalesce(
    properties.additionalData.PackageType,   ← novo caminho
    _scanner.mdvm.category,                  ← caminho intermediário
    _scanner.mdvm.PackageType                ← caminho antigo (mesmo campo, casing diferente)
)
```

Regra: **sempre coalesce quando o campo tem histórico de mudança**.
Ordem = mais provável primeiro.

## 3. Explorando ARG do zero

Duas ferramentas equivalentes:

### 3.1. Azure Portal → Resource Graph Explorer

`portal.azure.com` → busca "Resource Graph Explorer" → cola a
query → **Directory scope** no topo. Padrão é a subscription
atual; troque para o MG quando quiser ver `cvedetails`.

Vantagens: autocomplete, formatação, view de resultados em tabela.
Ideal para exploração inicial.

### 3.2. Terminal (`az graph query`)

```bash
az graph query -q '
securityresources
| where type == "microsoft.security/cvedetails"
| limit 5
' --output json | jq '.data[0]'
```

Se o retorno for `[]`, uma de três coisas:

- Você não está no scope certo (adicione `--management-groups <MG_ID>`).
- Você não tem permissão (precisa `Security Reader` no scope).
- O tipo de recurso realmente não existe naquele scope.

Distinguir os três:

```bash
# scope subscription — pode falhar por scope, não por auth
az graph query -q "securityresources | where type == 'microsoft.security/cvedetails' | count" 

# scope MG — falha por auth se não tiver Security Reader
az graph query -q "securityresources | where type == 'microsoft.security/cvedetails' | count" \
    --management-groups <MG_ID>
```

`count == 0` no MG e a query rodou sem erro = **você tem
permissão, o tipo está vazio nesse MG**. Isso não é sucesso, é
diagnóstico.

## 4. Descoberta de campos

Quando você não sabe o formato de um recurso, três primitivas te
salvam.

### 4.1. `bag_keys()` — lista chaves de um objeto dinâmico

```kusto
securityresources
| where type == "microsoft.security/cvedetails"
| take 1
| extend keys = bag_keys(properties)
| project keys
```

Retorna a lista de chaves de `properties`. Fundamental para
descobrir se um campo existe **sem chutar**. Roda com `take 1`
para não puxar dataset inteiro.

### 4.2. `mv-expand` + amostra pequena

Para arrays / objetos aninhados:

```kusto
securityresources
| where type == "microsoft.security/cvedetails"
| take 3
| project cvss = properties.cvss
```

Retorna 3 linhas com o conteúdo bruto do sub-objeto `cvss`.
Ideal pra descobrir se é dict (`{"3.0": {...}, "4.0": null}`) ou
array (`[{"Key": "3.0", ...}]`) — a diferença muda tudo na hora
de extrair.

### 4.3. `distinct` para descobrir valores possíveis

```kusto
securityresources
| where type == "microsoft.security/cvedetails"
| project sev = tostring(properties.severity), st = tostring(properties.status)
| distinct sev, st
```

Descobre os valores reais de `severity` (`"Critical"`, `"High"`,
`"Medium"`, `"Low"`, `""`) e `status` (`""`, `"Reject"`). Base pra
escrever filtros que não deixam dado passar.

### 4.4. Portal — "View details" no recurso individual

Selecione uma linha no Resource Graph Explorer → clique **"View
details"** → aba **JSON**. Você vê a estrutura completa do recurso.
Esse foi o método que gerou o payload em
`docs/mdvm-cvedetails-schema-2026-08.md`.

## 5. Debug — "por que este campo veio null?"

Fluxo padrão quando o CSV cospe `unknown` / `0.0` / campo vazio
onde não deveria.

### Passo 1 — reproduzir o campo isolado

Se `cvssScore` vem 0.0, isole:

```kusto
securityresources
| where type == "microsoft.security/assessments"
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| take 5
| mv-expand cve = parse_json(tostring(properties.additionalData.CvesDetails))
| project cveId = tostring(cve.CveId),
          cvss_inline = todouble(cve.Cvss[0].Value.Base),
          cvss_raw    = tostring(cve.Cvss)
```

Se `cvss_raw` vier `""` ou `[]` — o dado sumiu do assessments. Vá pro passo 2.
Se `cvss_raw` vier populado mas `cvss_inline` = null — mudou o formato do array. Investigar `bag_keys(cve.Cvss[0])`.

### Passo 2 — procurar o dado em outro tipo de recurso

```kusto
securityresources
| distinct type
| where type contains "security"
| order by type asc
```

Lista todos os tipos de `securityresources`. Se `cvedetails`
aparece, o dado provavelmente migrou pra lá.

### Passo 3 — contar linhas por caminho

Antes de mudar a KQL, medir onde o dado está:

```kusto
securityresources
| where type == "microsoft.security/cvedetails"
| summarize
    total = count(),
    com_cvss_40 = countif(isnotnull(properties.cvss["4.0"].base)),
    com_cvss_30 = countif(isnotnull(properties.cvss["3.0"].base)),
    com_cvss_20 = countif(isnotnull(properties.cvss["2.0"].base)),
    rejeitadas  = countif(tostring(properties.status) =~ "Reject")
```

Aqui você descobre coisas como "40k CVEs, 12k só têm 3.0, 8k só
têm 4.0, 500 estão rejeitadas". Base pra decidir a ordem do
`coalesce`.

### Passo 4 — comparar com o Portal

`portal.azure.com` → Defender for Cloud → Recommendations → filtrar
por container → pick uma CVE que deveria aparecer no CSV → ver os
valores humanos. Se o portal mostra CVSS 7.5 e nossa CSV mostra 0.0,
o problema **é** nossa query, não o dado.

## 6. Como Microsoft "muda tudo" — casos reais

Dois incidentes documentados neste repo:

### 6.1. Retiramento do `subassessments` (2026-07-31)

**Sintoma**: query voltou 0 linhas do dia pra noite.

**Causa**: Microsoft aposentou
`microsoft.security/assessments/subassessments` (era o tipo grouped
que a query original usava com key `c0b7cfc6-...`).

**Descoberta**:
```kusto
// Antes retornava milhares:
securityresources | where type == "microsoft.security/assessments/subassessments" | count
// -> 0
```

Rodei `securityresources | distinct type` e vi que só sobrou
`microsoft.security/assessments`. Documentação Microsoft confirmou
migração pro modelo "individual-recommendations".

**Fix**: reescrever entry point pra `microsoft.security/assessments`
+ 4 where-clauses (SoftwareUpdate + containerimage + Source == Azure).

### 6.2. Bug do CVSS `"3.1"` (2026-08)

**Sintoma**: `cvssScore` = 0.0 em CVEs que claramente têm score
no Portal.

**Causa**: enriquecimento CVE migrou pra
`microsoft.security/cvedetails` (MG scope). Uma tentativa anterior
tinha usado `properties.cvss['3.1'].base` — mas o schema real só
tem as chaves `"4.0"`, `"3.0"`, `"2.0"`. Chave `"3.1"` **nunca
existiu**. Coalesce silenciosamente retornava null pra toda CVE
que só tinha CVSS 3.x.

**Descoberta**:
```kusto
securityresources
| where type == "microsoft.security/cvedetails"
| take 1
| extend chaves_cvss = bag_keys(properties.cvss)
| project chaves_cvss
// -> ["3.0", "2.0", "4.0"]
```

`bag_keys` revela a verdade em uma query. Sem isso, é chute
baseado em intuição ("mas 3.1 existe na spec, deve estar aqui!").

**Fix**: coalesce `4.0 → 3.0 → 2.0`, e um teste de guardrail
(`tests/test_defender_query_migration.py::test_no_cvss_31_key`)
que **falha se o literal `'3.1'` reaparecer na KQL**.

### 6.3. Padrão que emerge

Toda vez que a Microsoft muda schema, o padrão de debug é:

1. **Falha silenciosa** — não vem erro, vem dado ruim.
2. **`bag_keys()`** revela onde o dado foi parar.
3. **`coalesce`** com múltiplos caminhos protege durante a transição.
4. **Teste de guardrail** que grava a lição, pra o próximo agente
   não repetir.

## 7. Ajustando a query no código

### Onde vive a KQL

`defender.sh`, entre as linhas onde diz `cat > "$QUERY_FILE" <<
ENDQUERY` e `ENDQUERY`. É um heredoc de bash com interpolação de
variáveis (`$EARLY_FILTER_B`, `$MIN_SCORE`, `$MAX_SCORE`).

Comentários acima do heredoc explicam **por que** cada parte
existe — leia antes de tocar. Se você mexer sem entender o comentário,
provavelmente vai regredir um bug que já foi resolvido.

### Fluxo de mudança

1. **Escreva o teste primeiro** em `tests/test_defender_query_migration.py`.
   Descreva a invariante em prosa no docstring, depois `assert` na regex.
2. **Rode `pytest tests/test_defender_query_migration.py -v`** — o novo
   teste falha (esperado).
3. **Ajuste a KQL** no heredoc do `defender.sh`.
4. **Rode `pytest`** — o novo teste passa, os 39 antigos continuam verdes.
5. **Rode `make check`** — pytest + ruff + pyright + bash -n + shellcheck.
6. **Debug num MG real com `--debug`** — flag do defender.sh que imprime
   a KQL gerada e roda um diagnóstico ARG. Confirme que retornou linhas
   antes de mergear.

### Regras de ouro

- **Não altere a ordem do `| project` final.** É contrato com
  `check_ocp.sh` → `group_findings.py` → `expandcsv.py` → `report.py`.
  Se precisar adicionar coluna, adicione **no fim** e atualize os
  testes de ordem.
- **Não remova o fallback inline.** Mesmo com JOIN funcionando,
  Microsoft pode reverter/atrasar publicação em algum MG. Fallback
  é gratuito.
- **Não use `join kind=inner`.** Se o direito ficar vazio, some com
  o dado. Sempre `leftouter`.
- **Sempre `toupper()` chaves de string em JOIN.** IDs de CVE aparecem
  em casing misto (`CVE-x` no assessments, `cve-x` no cvedetails.name).

## 8. Checklist de PR quando o schema muda

Copie pra descrição do PR:

- [ ] Reproduzi o problema em um Resource Graph Explorer sandbox
- [ ] Rodei `bag_keys()` no recurso afetado, colei o resultado no PR
- [ ] Comparei os valores com o Portal → JSON view em pelo menos 3 CVEs
- [ ] Atualizei `docs/mdvm-cvedetails-schema-2026-08.md` (ou spec
      equivalente) com a amostra nova
- [ ] Adicionei teste de guardrail em `tests/test_defender_query_migration.py`
      que falha se a mudança regredir
- [ ] Mantive fallback pra caminho antigo via `coalesce` (não removi)
- [ ] Preservei ordem das 18 colunas do CSV
- [ ] `make check` verde local
- [ ] Testei `defender.sh --debug --min-score 9 --max-score 10 --acr-name <acr>`
      e a KQL gerada retorna linhas
- [ ] `AGENTS.md` atualizado se a arquitetura mudou

## Apêndice — snippets prontos pra copiar

### A. Sanidade rápida — o tipo existe no meu scope?

```bash
az graph query -q "securityresources | where type == 'microsoft.security/cvedetails' | count"
az graph query -q "securityresources | where type == 'microsoft.security/cvedetails' | count" --management-groups <MG_ID>
```

### B. Explorar keys de properties

```bash
az graph query -q '
securityresources
| where type == "microsoft.security/cvedetails"
| take 1
| project keys = bag_keys(properties)
' --management-groups <MG_ID> --output json | jq '.data'
```

### C. Cvss dict layout (o teste do "3.1")

```bash
az graph query -q '
securityresources
| where type == "microsoft.security/cvedetails"
| take 1
| extend chaves = bag_keys(properties.cvss)
| project chaves
' --management-groups <MG_ID>
```

### D. Ver o dado bruto de uma CVE específica

```bash
az graph query -q '
securityresources
| where type == "microsoft.security/cvedetails"
| where tostring(properties.cveId) == "CVE-2024-6179"
| project properties
' --management-groups <MG_ID> --output json | jq '.data[0].properties'
```

### E. Testar o join sem rodar o script inteiro

```bash
az graph query -q '
let cvedetails =
    securityresources
    | where type == "microsoft.security/cvedetails"
    | where tostring(properties.status) !~ "Reject"
    | extend cveIdJoin = toupper(tostring(properties.cveId))
    | project cveIdJoin, cvss = todouble(coalesce(
        properties.cvss["4.0"].base,
        properties.cvss["3.0"].base,
        properties.cvss["2.0"].base));
securityresources
| where type == "microsoft.security/assessments"
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| take 100
| mv-expand cve = parse_json(tostring(properties.additionalData.CvesDetails))
| extend cveIdJoin = toupper(tostring(cve.CveId))
| join kind=leftouter cvedetails on cveIdJoin
| project cveId = tostring(cve.CveId), cvss
| where isnotempty(cveId)
' --management-groups <MG_ID> --output table
```

Se retornar linhas com `cvss` populado → JOIN está funcionando.
Se todas vierem null → problema de scope ou permissão no MG.

## Referências

- `docs/mdvm-cvedetails-schema-2026-08.md` — schema completo do
  `microsoft.security/cvedetails` com amostra real.
- `docs/mdvm-individual-migration.md` — histórico da migração
  `subassessments` → `assessments` (2026-07-31).
- `tests/test_defender_query_migration.py` — 39 invariantes que
  qualquer mudança na KQL precisa manter verdes.
- Microsoft: [CVE details data consumption in ARG](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#update-to-cve-details-data-consumption-in-azure-resource-graph)
- Kusto: [`bag_keys()`](https://learn.microsoft.com/en-us/kusto/query/bag-keys-function),
  [`mv-expand`](https://learn.microsoft.com/en-us/kusto/query/mv-expand-operator),
  [`join`](https://learn.microsoft.com/en-us/kusto/query/join-operator).
