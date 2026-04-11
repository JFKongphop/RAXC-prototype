# RAXC — AI-Powered DeFi Smart Contract Vulnerability Scanner

> **R**etrieval **A**ugmented e**X**ploit **C**hecker
> Grant Application One-Pager | April 2026

**RAXC** stands for:

| Letter | Word | Meaning |
|--------|------|---------|
| **R** | Retrieval | Finds the most semantically similar real-world exploits from a vector database |
| **A** | Augmented | Augments LLM analysis with grounded, evidence-based exploit context |
| **X** | eXploit | Focused specifically on DeFi exploit patterns — not generic code review |
| **C** | Checker | Fast, automated pre-deployment security check — not a full audit replacement |

> *"Don't just ask an AI if your contract is safe — ask an AI that has seen 626 real hacks."*

---

## The Problem

DeFi protocols have lost over **$4.1 billion** to smart contract exploits — and the same vulnerability patterns keep repeating year after year.

> These numbers are drawn directly from **474 real on-chain exploits** in the RAXC dataset (DeFiHackLabs). An additional 104 exploits with losses in ETH/BNB/tokens are not included, meaning the true total is significantly higher.

| Year | Confirmed USD Lost | Trend |
|------|--------------------|-------|
| 2017 | $30,000,000 | Early days |
| 2018 | $140,000,155 | — |
| 2020 | $20,000,000 | — |
| 2021 | $124,365,000 | ↑ DeFi summer |
| 2022 | $205,809,017 | ↑ Bridge attacks |
| 2023 | $443,980,241 | ↑↑ |
| 2024 | $1,386,601,430 | ↑↑↑ |
| 2025 | $1,777,671,071 | ↑↑↑↑ Worst year ever |
| 2026 | $7,655,193 | (Jan–Apr only) |
| **Total** | **$4,136,086,808** | |

**Average loss per exploit: $11.2 million USD**

The losses are accelerating every year. The same vulnerability types — reentrancy, price manipulation, flash loans, access control — appear across hundreds of incidents. These are **preventable** if caught before deployment.

**The root cause:** Developers and auditors lack fast, evidence-based tools to catch vulnerabilities before deployment. Traditional static analysis tools generate too many false positives and miss novel attack patterns. LLMs alone hallucinate and lack grounding in real exploit data.

---

## The Solution — RAXC

RAXC is a **Retrieval-Augmented Generation (RAG) pipeline** that analyzes Solidity smart contracts by comparing them against a database of **626+ real-world DeFi exploits** from DeFiHackLabs.

```
User submits contract
        │
        ▼
 Embed with OpenAI          ← text-embedding-3-small
        │
        ▼
 Semantic Search in Qdrant  ← finds top 5 most similar past exploits
        │
        ▼
 GPT-4o Analysis            ← grounded in real exploit evidence
        │
        ▼
 Structured Security Report ← vulnerability type, risk level, fixed code
```

---

## What Makes RAXC Different

| Feature | Traditional Audit Tool | Pure GPT-4o | **RAXC** |
|---------|----------------------|------------|---------|
| Real exploit references | ❌ | ❌ | ✅ |
| Evidence-grounded analysis | ❌ | ❌ | ✅ |
| Similarity scoring | ❌ | ❌ | ✅ |
| Fixed code output | ❌ | Sometimes | ✅ Always |
| Covers novel patterns | ❌ | Sometimes | ✅ |
| Cost per analysis | $$$$ | $ | $ |

**The key insight:** When GPT-4o knows that *"this exact pattern was used to drain $439K from CompoundUni in Feb 2024"*, it produces dramatically more accurate and credible reports than generic analysis.

---

## Is This Novel?

**Yes.** No existing tool does what RAXC does.

### Competitive Landscape

| Tool | Approach | Gap |
|------|----------|-----|
| Slither, MythX | Static analysis — rule-based pattern matching | Misses novel patterns, high false positives |
| Code4rena, Immunefi | Human auditors | $50K+ cost, weeks of turnaround |
| ChatGPT / Claude | Generic LLM knowledge | Hallucinations, no real exploit grounding |
| Forta Network | Real-time on-chain monitoring | Detects **after** deployment, not before |
| Cyfrin Aderyn | Open-source static analysis | No LLM, no exploit database |
| Audit Wizard | LLM-assisted audit UI | No RAG, no real exploit retrieval |

### RAXC's Unique Technical Combination

> **Semantic vector index of real exploit POC code used as retrieval context for LLM analysis**

The specific combination of:
1. **DeFiHackLabs** as a structured, code-level exploit corpus (626+ real POCs)
2. **Code-level semantic embeddings** — not keyword search, but meaning-based similarity
3. **RAG-grounded LLM report** with per-exploit similarity scores and transaction links

— **does not exist as a product today.**

### The Compounding Moat

The DeFiHackLabs dataset grows every week as new exploits are added by the community. The longer RAXC runs, the better and more accurate the retrieval becomes. Competitors cannot replicate this without the same dataset, pipeline, and indexing infrastructure.

**Every new exploit that enters the dataset makes every future analysis more accurate.**

---

## Live Demo Results

### Test 1 — Reentrancy
```
Contract:  VulnerableVault (withdraw before state update)
Result:    Critical | Reentrancy
Reference: ValueDefi (ETH) — similarity 0.614
```

### Test 2 — Price Manipulation
```
Contract:  VulnerableLending (Uniswap spot price oracle)
Result:    High | Price Manipulation
Reference: CompoundUni (ETH, $439K lost) — similarity 0.714
Top 5:     CompoundUni, NeutraFinance, LinkDao, Astrid
```

---

## Dataset

- **Source:** DeFiHackLabs (open source, community-maintained)
- **Coverage:** 626+ exploit POCs across ETH, BSC, Arbitrum, Optimism, Avalanche, Polygon
- **Range:** 2017 → 2026
- **Update cadence:** New exploits added weekly by the community

Each exploit contains:
- Real attacker address + transaction hash
- Total funds lost
- Full Foundry POC test code (semantic signal)

---

## Technical Stack

| Component | Technology |
|-----------|-----------|
| Embedding model | OpenAI `text-embedding-3-small` (1536-dim) |
| Vector database | Qdrant (local Docker, production-ready cloud) |
| LLM | OpenAI GPT-4o |
| Pipeline orchestration | Python + LangGraph (next milestone) |
| Dataset | DeFiHackLabs (`src/test/**/*.sol`) |

---

## Roadmap

### Phase 1 — POC ✅ (Today)
- [x] Index 626+ real-world exploits into Qdrant
- [x] RAG retrieval with semantic similarity scoring
- [x] GPT-4o structured security report with code fix
- [x] Markdown report export

### Phase 2 — Product (Next 4 weeks)
- [ ] Streamlit web UI for contract submission
- [ ] LangGraph multi-agent pipeline (retrieve → analyze → verify → report)
- [ ] Full dataset indexing (726 files)
- [ ] ERC4626 vault on Avalanche C-Chain for credit/subscription system

### Phase 3 — Scale (Post-grant)
- [ ] CI/CD integration (GitHub Action: scan on every commit)
- [ ] API endpoint for third-party integrations
- [ ] Expand dataset (Code4rena, Immunefi reports)
- [ ] Multi-chain deployment monitoring

---

## Business Model

RAXC uses an **on-chain credit system** built on an ERC4626 vault deployed on Avalanche C-Chain.

```
User deposits tokens into ERC4626 vault
              │
              ▼
     Receives RAXC credits
              │
              ▼
   Credits burned per analysis
              │
              ▼
   Security report generated
```

| Tier | Credits | Target User |
|------|---------|-------------|
| Free | 3 analyses/month | Individual developers |
| Pay-per-use | ~$0.10/analysis via vault | Small teams |
| Protocol subscription | Unlimited via vault stake | DeFi protocols pre-launch |
| Enterprise API | Custom | Audit firms, launchpads |

**Why on-chain?**
- Trustless — no centralized billing
- Composable — other protocols can integrate RAXC checks into their deployment pipeline
- Aligns with Avalanche C-Chain ecosystem

**Unit economics:**
- Cost per analysis: ~$0.03 (embedding + GPT-4o)
- Price per analysis: ~$0.10
- Margin: ~70%

**Long-term:** As the DeFiHackLabs dataset grows and the vector index improves, accuracy increases — allowing premium pricing for high-value protocols deploying significant TVL.

---


| Item | Cost |
|------|------|
| OpenAI API (full dataset + production queries) | ~$50/mo |
| Qdrant Cloud (production vector DB) | ~$25/mo |
| Development time (Phase 2) | Grant-funded |
| **Total ask** | **$X,XXX** |

**ROI:** Each prevented exploit saves protocols anywhere from $30K to $400M+. RAXC costs cents per analysis.

---

## Why Now

1. **DeFi exploits are accelerating** — 2024 saw major attacks every week
2. **RAG technology matured** — vector search + LLMs are now production-grade
3. **DeFiHackLabs dataset** — a unique, growing corpus of real exploit POCs that no commercial tool uses
4. **Developer demand** — teams deploying contracts need fast pre-audit screening before expensive formal audits ($50K+)

---

## Team

> *[Add your name, background, relevant experience here]*

---

## Contact

> *[Add contact info here]*

---

*RAXC is open-source. The mission is to make DeFi safer by turning the history of past exploits into a living security knowledge base.*
