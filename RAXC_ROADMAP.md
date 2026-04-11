# RAXC — Smart Contract Security Scanner
## Product Roadmap

> **RAXC** is an AI-powered smart contract vulnerability scanner that detects exploit patterns by referencing real-world DeFi hacks. Developers submit their contracts before deployment and receive an instant, grounded security report.

---

## Phase 2 — LangGraph Orchestration
**Goal:** Transform the raw POC pipeline into a robust, production-ready AI agent

### What we build:
- Wrap the RAG pipeline into a structured **LangGraph graph** with 3 core nodes:
  - `retrieve_node` — similarity search against DeFiHackLabs exploit database
  - `analyze_node` — GPT-4o analyzes contract with retrieved exploit context
  - `report_node` — formats output into structured security report
- Add **state management** so the pipeline tracks context across nodes
- Add **retry logic** and conditional edges for failed retrievals
- Add **streaming output** so users see the report being generated in real time

### Output:
A reliable, orchestrated AI agent pipeline that produces consistent structured reports from any Solidity contract input.

---

## Phase 3 — Full Dataset Indexing
**Goal:** Maximize retrieval quality by indexing the entire DeFiHackLabs dataset

### What we build:
- Index all **500+ exploit POC files** from DeFiHackLabs into Qdrant
- Cover exploits across **ETH, BSC, Arbitrum, Optimism, Polygon** chains
- Enrich each record with metadata: chain, date, total lost, vulnerability type, attack tx
- Upgrade embeddings from `text-embedding-3-small` to **Voyage AI `voyage-code-2`** for superior code-level similarity
- Implement **hybrid search** (dense + sparse) for more accurate retrieval

### Output:
A comprehensive exploit knowledge base covering years of real DeFi hacks, giving RAXC's analysis deep, battle-tested context.

---

## Phase 4 — On-Chain Credit Vault
**Goal:** Trustless, on-chain payment system for the RAXC platform

### What we build:
- **ERC4626 vault contract** deployed on target chains:
  - Avalanche C-Chain (USDC deposits)
  - Initia (for Initia ecosystem builders)
- Users deposit USDC → receive vault shares as credit balance
- Backend acts as a **trusted operator** — after each analysis, deducts exact cost from user's vault balance
- **Fee model:** `user pays = AI cost × 1.1` (10% platform fee on top of actual OpenAI token cost)
- Token cost calculated precisely using OpenAI's `usage` response object:
  ```
  actual_cost = (prompt_tokens × $2.50/1M) + (completion_tokens × $10.00/1M)
  user_charge  = actual_cost × 1.10
  ```
- Users can top up, check balance, and withdraw unused credits at any time

### Output:
A transparent, on-chain credit system that ties AI usage costs directly to blockchain payments — no black box pricing.

---

## Phase 5 — Frontend & Developer Experience
**Goal:** Make RAXC accessible to any developer with zero friction

### What we build:
- Clean **web interface** with:
  - Solidity contract input (paste or upload `.sol` file)
  - One-click **Analyze** button
  - Live streaming report output
  - Credit balance display from vault
  - Top-up flow (connect wallet → deposit USDC)
- **Structured report UI** showing:
  - Risk level badge (Critical / High / Medium / Low)
  - Vulnerability type
  - Matched exploit reference with link to DeFiHackLabs
  - Explanation and fix recommendation
- **API endpoint** for CI/CD integration — developers can plug RAXC into their deployment pipeline

### Output:
A polished, developer-friendly product that any builder can use before deploying their contracts.

---

## Phase 6 — Ecosystem Expansion & Trustless Upgrade
**Goal:** Scale RAXC across ecosystems and move toward a fully trustless architecture

### What we build:

**Multi-chain support:**
- Expand vault deployment to more EVM chains
- Support chain-specific exploit datasets (Avalanche exploits, Initia-specific patterns)
- Position RAXC as the default pre-deployment security check for each ecosystem

**Trustless payment (zkTLS):**
- Integrate **Reclaim Protocol / tlsnotary** to generate ZK proofs of OpenAI API responses
- Vault contract verifies ZK proof before deducting — eliminating trust in the backend operator
- Users no longer need to trust RAXC's backend to handle their credits honestly

**Dataset expansion:**
- Add **Immunefi bug reports** and **Code4rena audit findings** to the knowledge base
- Continuous indexing of new exploits as they happen

**RAXC Agent (autonomous monitoring):**
- Deploy RAXC as an **autonomous agent** that monitors newly deployed contracts on-chain
- Automatically flags suspicious contracts in real time
- Sends alerts to protocol teams before exploits happen

### Output:
A fully trustless, multi-chain, autonomous security infrastructure for the DeFi ecosystem.

---

## Summary

| Phase | Focus | Key Deliverable |
|---|---|---|
| **2** | LangGraph Orchestration | Robust AI agent pipeline |
| **3** | Full Dataset Indexing | 500+ exploits in Qdrant |
| **4** | On-Chain Credit Vault | ERC4626 on Avalanche + Initia |
| **5** | Frontend & Dev UX | Web app + API endpoint |
| **6** | Ecosystem & Trustless | zkTLS + multi-chain + autonomous agent |

---

## Why RAXC Matters

- **$8.5B+ lost** to DeFi exploits since 2020
- Most audit tools use static rule-based analysis — RAXC uses **real exploit data**
- Developers can audit their own contracts **before deployment** in seconds
- On-chain payment vault makes the platform **transparent and verifiable**
- Built for the ecosystems that need it most — **Avalanche, Initia, and beyond**
