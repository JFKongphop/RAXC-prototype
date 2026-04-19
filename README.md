# RAXC — AI-Powered DeFi Smart Contract Vulnerability Scanner

> **R**etrieval **A**ugmented e**X**ploit **C**hecker

*"Don't just ask an AI if your contract is safe — ask an AI that has seen 726 real hacks."*

RAXC is a RAG-powered security scanner that detects smart contract vulnerabilities by comparing your Solidity code against a database of **726+ real-world DeFi exploits** from DeFiHackLabs. Instead of generic LLM analysis, every finding is grounded in evidence from actual on-chain attacks.

---

## How It Works

```
User submits Solidity contract
        │
        ▼
  Embed with OpenAI          ← text-embedding-3-small
        │
        ▼
  Semantic Search in Qdrant  ← top 5 most similar past exploits
        │
        ▼
  GPT-4o Analysis            ← grounded in real exploit context
        │
        ▼
  Structured Security Report ← vulnerability type, risk level, fixed code
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| API Server | Rust + Axum |
| RAG Pipeline | Python + LangGraph |
| Vector DB | Qdrant |
| Embeddings | OpenAI `text-embedding-3-small` |
| LLM | OpenAI GPT-4o |
| Frontend | Next.js 14 + TypeScript |
| Deployment | Fly.io (Docker) |

---

## Repository Structure

```
├── src/               # Rust API server & CLI analyzer
│   ├── main.rs        # CLI: analyze a .sol file from the command line
│   ├── api.rs         # HTTP server (POST /analyze, GET /reports/:file)
│   └── lib.rs         # Shared RAG logic (embed, retrieve, analyze)
├── python/            # Python RAG pipeline scripts
│   ├── indexer_protocol.py   # Index DeFiHackLabs protocol exploits
│   ├── indexer_case.py       # Index DeFiVulnLabs case patterns
│   ├── analyze.py            # Run analysis locally
│   └── evaluate.py           # Evaluate retrieval quality
├── frontend/          # Next.js web UI
├── datasets-protocol-exploit/  # DeFiHackLabs exploit POC dataset
├── datasets-case-exploit/      # DeFiVulnLabs educational patterns
├── reports/           # Generated markdown security reports
├── Dockerfile         # Multi-stage build for the Rust API
├── fly.toml           # Fly.io deployment config
└── Makefile           # Dev workflow shortcuts
```

---

## Prerequisites

- [Rust](https://rustup.rs/) (1.80+)
- [Docker](https://www.docker.com/)
- [Python](https://python.org/) 3.11+
- OpenAI API key
- Node.js 20+ (for frontend)

---

## Quick Start

### 1. Clone with submodules

```bash
git clone --recurse-submodules https://github.com/<your-org>/RAXC-prototype.git
cd RAXC-prototype
```

### 2. Set environment variables

```bash
cp .env.example .env
# Fill in:
# OPENAI_API_KEY=sk-...
# QDRANT_URL=http://localhost:6333
# QDRANT_API_KEY=          # leave empty for local
```

### 3. Start Qdrant

```bash
make start
# or manually:
docker run -d --name qdrant -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

### 4. Index the exploit datasets

```bash
pip install -r datasets-protocol-exploit/requirements.txt
python3 python/indexer_protocol.py   # indexes ~500+ DeFiHackLabs exploits
python3 python/indexer_case.py       # indexes DeFiVulnLabs patterns
```

Check indexed count:
```bash
make check
```

### 5. Run analysis

**CLI (Rust):**
```bash
cargo run --bin analyze -- path/to/YourContract.sol
```

**Python:**
```bash
python3 python/analyze.py path/to/YourContract.sol
```

**Demo with built-in sample:**
```bash
make demo
```

---

## API Server

### Run locally

```bash
cargo run --bin api
# Server starts at http://localhost:8080
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/analyze` | Analyze a Solidity contract |
| `GET` | `/reports/:file` | Download generated markdown report |
| `GET` | `/health` | Liveness check |

### Example request

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "contract": "pragma solidity ^0.8.0; contract Vault { ... }",
    "name": "MyVault"
  }'
```

### Example response

```json
{
  "download_url": "/reports/RAXC_MyVault_20260416_133558.md",
  "vulnerability_found": "Yes",
  "risk_level": "Critical",
  "vulnerability_type": "Reentrancy",
  "summary": "The withdraw function is vulnerable to reentrancy...",
  "top_exploit": "DFX Finance — $7.5M lost (Nov 2022)"
}
```

---

## Frontend

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

Paste any Solidity contract and click **Analyze** to receive a structured security report with matched exploit references.

---

## Docker Deployment

Build and run the API container:

```bash
docker build -t raxc-api .
docker run -p 8080:8080 --env-file .env raxc-api
```

### Fly.io

```bash
fly deploy
```

The app is configured in [fly.toml](fly.toml) targeting the `ams` region. Pass secrets via `fly secrets set OPENAI_API_KEY=... QDRANT_URL=... QDRANT_API_KEY=...`.

---

## Makefile Reference

| Target | Description |
|--------|-------------|
| `make start` | Start Qdrant Docker container |
| `make check` | Show indexed exploit count |
| `make index` | Re-index all exploit files |
| `make demo` | Run analysis on built-in sample |
| `make analyze FILE=x.sol` | Analyze a specific contract |
| `make run` | Full flow: start → check → demo |
| `make stop` | Stop Qdrant |
| `make reports` | List generated reports |
| `make eval` | Run full evaluation (10 contracts) |
| `make eval-quick` | Run quick evaluation (5 contracts) |

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 — POC | ✅ Done | RAG pipeline + CLI + API server |
| Phase 2 — LangGraph | 🔄 In progress | Multi-node agent with retry & streaming |
| Phase 3 — Full Indexing | 📋 Planned | All 500+ exploits, Voyage AI embeddings, hybrid search |
| Phase 4 — On-Chain Credit Vault | 📋 Planned | ERC4626 vault for trustless per-analysis payment |
| Phase 5 — Frontend & CI/CD API | 📋 Planned | Web UI, wallet top-up, pipeline integration |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | ✅ | OpenAI API key |
| `QDRANT_URL` | ✅ | Qdrant instance URL (e.g. `http://localhost:6333`) |
| `QDRANT_API_KEY` | ❌ | Required for Qdrant Cloud; omit for local |

---

## License

MIT
