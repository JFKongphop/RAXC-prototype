# RAXC POC — Context & Build Plan

## What is RAXC?
AI-powered smart contract vulnerability scanner. User submits a Solidity contract → RAXC retrieves similar real-world exploits from DeFiHackLabs dataset → sends to OpenAI for analysis → returns structured security report.

---

## Stack
- **RAG Pipeline**: Python + LangGraph
- **Vector DB**: Qdrant (local Docker)
- **Embeddings**: OpenAI `text-embedding-3-small`
- **LLM**: OpenAI GPT-4o
- **Dataset**: DeFiHackLabs (`src/test/**/*.sol`)

---

## Dataset Structure
Each `.sol` file in DeFiHackLabs follows this format:

```solidity
// @KeyInfo - Total Lost : $8.5k
// Attacker : https://bscscan.com/address/0x...
// Attack Contract : https://bscscan.com/address/0x...
// Vulnerable Contract : https://bscscan.com/address/0x...
// Attack Tx : https://bscscan.com/tx/0x...

// @Analysis
// Post-mortem : ...
```

- File path encodes: `src/test/{date}/{exploit_name}_exp.sol`
- Each file = one exploit POC written as a Foundry test
- Chain detected from comment URLs (bscscan = BSC, etherscan = ETH, arbiscan = Arbitrum)

---

## Qdrant Payload Schema
```json
{
  "exploit_name": "proxy_b7e1",
  "date": "2024-11",
  "total_lost": "$8.5k",
  "attacker": "https://bscscan.com/address/0x...",
  "vulnerable_contract": "https://bscscan.com/address/0x...",
  "attack_tx": "https://bscscan.com/tx/0x...",
  "chain": "BSC",
  "code": "<full solidity file content>"
}
```

---

## POC Build Steps

### Step 1 — Clone Dataset
```bash
git clone https://github.com/SunWeb3Sec/DeFiHackLabs.git
```

### Step 2 — Run Qdrant
```bash
docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant
```
Dashboard: `http://localhost:6333/dashboard`

### Step 3 — Install Dependencies
```bash
pip install qdrant-client openai python-dotenv langchain-openai langgraph
```

### Step 4 — Indexing Script
File: `indexer.py`

```python
import os
import re
import uuid
import glob
from pathlib import Path
from openai import OpenAI
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
from dotenv import load_dotenv

load_dotenv()

openai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
qdrant = QdrantClient("localhost", port=6333)

COLLECTION = "defi_exploits"
EMBED_MODEL = "text-embedding-3-small"
VECTOR_SIZE = 1536

def setup_collection():
    existing = [c.name for c in qdrant.get_collections().collections]
    if COLLECTION not in existing:
        qdrant.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE)
        )
        print(f"Created collection: {COLLECTION}")

def detect_chain(content: str) -> str:
    if "bscscan" in content: return "BSC"
    if "arbiscan" in content: return "Arbitrum"
    if "optimistic.etherscan" in content: return "Optimism"
    if "polygonscan" in content: return "Polygon"
    if "etherscan" in content: return "ETH"
    return "unknown"

def parse_sol_file(filepath: str) -> dict:
    content = open(filepath, encoding="utf-8", errors="ignore").read()
    path = Path(filepath)

    lost = re.search(r'Total Lost\s*:\s*(.+)', content)
    attacker = re.search(r'Attacker\s*:\s*(.+)', content)
    vuln = re.search(r'Vulnerable Contract\s*:\s*(.+)', content)
    attack_tx = re.search(r'Attack Tx\s*:\s*(.+)', content)

    return {
        "exploit_name": path.stem.replace("_exp", ""),
        "date": path.parts[-2],
        "total_lost": lost.group(1).strip() if lost else "unknown",
        "attacker": attacker.group(1).strip() if attacker else "unknown",
        "vulnerable_contract": vuln.group(1).strip() if vuln else "unknown",
        "attack_tx": attack_tx.group(1).strip() if attack_tx else "unknown",
        "chain": detect_chain(content),
        "code": content
    }

def embed(text: str) -> list[float]:
    # truncate to avoid token limit
    text = text[:6000]
    response = openai.embeddings.create(input=text, model=EMBED_MODEL)
    return response.data[0].embedding

def index_file(filepath: str):
    try:
        payload = parse_sol_file(filepath)
        vector = embed(payload["code"])
        qdrant.upsert(
            collection_name=COLLECTION,
            points=[PointStruct(
                id=str(uuid.uuid4()),
                vector=vector,
                payload=payload
            )]
        )
        print(f"Indexed: {payload['exploit_name']} ({payload['date']}) [{payload['chain']}]")
    except Exception as e:
        print(f"Failed {filepath}: {e}")

if __name__ == "__main__":
    setup_collection()

    # For POC: index only 2024-11 to test fast
    # Change to "**/*.sol" for full dataset
    files = glob.glob("DeFiHackLabs/src/test/2024-11/*.sol")
    print(f"Found {len(files)} files to index...")

    for f in files:
        index_file(f)

    print("Done. Check http://localhost:6333/dashboard")
```

### Step 5 — Retrieval + OpenAI Analysis Script
File: `analyze.py`

```python
import os
from openai import OpenAI
from qdrant_client import QdrantClient
from dotenv import load_dotenv

load_dotenv()

openai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
qdrant = QdrantClient("localhost", port=6333)

COLLECTION = "defi_exploits"
EMBED_MODEL = "text-embedding-3-small"

def embed(text: str) -> list[float]:
    text = text[:6000]
    response = openai.embeddings.create(input=text, model=EMBED_MODEL)
    return response.data[0].embedding

def retrieve(contract_code: str, top_k: int = 5) -> list:
    vector = embed(contract_code)
    results = qdrant.search(
        collection_name=COLLECTION,
        query_vector=vector,
        limit=top_k
    )
    return results

def build_context(results: list) -> str:
    context = ""
    for i, r in enumerate(results):
        p = r.payload
        context += f"""
--- Exploit {i+1}: {p['exploit_name']} ({p['date']}) ---
Chain: {p['chain']}
Total Lost: {p['total_lost']}
Attack Tx: {p['attack_tx']}
Code Snippet:
{p['code'][:1500]}
"""
    return context

def analyze(contract_code: str) -> str:
    results = retrieve(contract_code)
    context = build_context(results)

    prompt = f"""You are a smart contract security expert.

Analyze the following contract for potential vulnerabilities.
Use the similar real-world exploit cases below as reference.

## Similar Exploit Cases from DeFiHackLabs:
{context}

## Contract to Analyze:
{contract_code}

## Output a structured security report:
- Vulnerability Found: Yes/No
- Risk Level: Critical / High / Medium / Low / None
- Vulnerability Type: (e.g. Reentrancy, Flash Loan, Access Control, etc.)
- Similar Exploit Reference: (which exploit case is most similar)
- Explanation: (what is the vulnerability and how could it be exploited)
- Recommendation: (how to fix it)
"""

    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000
    )

    return response.choices[0].message.content

if __name__ == "__main__":
    # Test with a sample contract
    sample_contract = """
    pragma solidity ^0.8.0;

    contract VulnerableVault {
        mapping(address => uint256) public balances;

        function deposit() external payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw() external {
            uint256 amount = balances[msg.sender];
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] = 0;
        }
    }
    """

    print("Analyzing contract...\n")
    report = analyze(sample_contract)
    print(report)
```

### Step 6 — .env File
```
OPENAI_API_KEY=sk-...
```

---

## Expected Output Report
```
- Vulnerability Found: Yes
- Risk Level: Critical
- Vulnerability Type: Reentrancy
- Similar Exploit Reference: proxy_b7e1 (2024-11)
- Explanation: The withdraw() function sends ETH before updating
  the balance, allowing a malicious contract to re-enter and
  drain funds repeatedly.
- Recommendation: Use ReentrancyGuard or update state before
  external calls (checks-effects-interactions pattern).
```

---

## Tonight's Checklist
- [ ] Clone DeFiHackLabs repo
- [ ] Run Qdrant via Docker
- [ ] Create `.env` with OpenAI API key
- [ ] Run `indexer.py` (2024-11 folder only for POC)
- [ ] Verify indexed data in Qdrant dashboard
- [ ] Run `analyze.py` with sample contract
- [ ] Confirm report output is correct

---

## Next Steps (After POC)
- [ ] Wrap pipeline in LangGraph nodes (retrieve → analyze → report)
- [ ] Index full DeFiHackLabs dataset
- [ ] Add ERC4626 vault on Avalanche C-Chain for credit system
- [ ] Build simple frontend for contract submission
- [ ] Submit to Initia Hackathon / Avax Grant / ETHGlobal

---

## Notes
- For POC use only `2024-11` folder (~20 files) to save API costs
- Full dataset has 500+ files — index later once pipeline is validated
- `text-embedding-3-small` is cheapest OpenAI embedding model, sufficient for POC
- Swap to `voyage-code-2` later for better code similarity if needed
