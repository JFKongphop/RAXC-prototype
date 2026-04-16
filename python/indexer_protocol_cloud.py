"""
RAXC Indexer (Cloud) — Index protocol exploit POCs into Qdrant Cloud.
Source: datasets-protocol-exploit/src/test/**/*.sol
Target collection: defi_protocols
Run: python3 indexer_protocol_cloud.py

Uses QDRANT_URL + QDRANT_API_KEY from .env to connect to Qdrant Cloud.
Falls back to local Docker if those vars are not set.
"""

import os
import re
import uuid
import glob
import time
from pathlib import Path
from openai import OpenAI
from qdrant_client.models import VectorParams, Distance, PointStruct
from python.qdrant_config import get_qdrant_client
from dotenv import load_dotenv

load_dotenv()

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
qdrant = get_qdrant_client()

COLLECTION    = "defi_protocols"
EMBED_MODEL   = "text-embedding-3-small"
VECTOR_SIZE   = 1536
BATCH_SIZE    = 10
CODE_TRUNCATE = 6000


# ---------------------------------------------------------------------------
# Collection setup
# ---------------------------------------------------------------------------

def setup_collection():
    existing = [c.name for c in qdrant.get_collections().collections]
    if COLLECTION not in existing:
        qdrant.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )
        print(f"[+] Created collection: {COLLECTION}")
    else:
        print(f"[=] Using existing collection: {COLLECTION}")


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def detect_chain(content: str) -> str:
    c = content.lower()
    if "bscscan" in c:
        return "BSC"
    if "arbiscan" in c:
        return "Arbitrum"
    if "optimistic.etherscan" in c or "optimism" in c:
        return "Optimism"
    if "polygonscan" in c:
        return "Polygon"
    if "basescan" in c:
        return "Base"
    if "snowtrace" in c or "avalanche" in c:
        return "Avalanche"
    if "etherscan" in c:
        return "ETH"
    return "unknown"


def parse_sol_file(filepath: str) -> dict:
    content = open(filepath, encoding="utf-8", errors="ignore").read()
    path = Path(filepath)

    lost      = re.search(r"Total Lost\s*:\s*(.+)", content)
    attacker  = re.search(r"Attacker\s*:\s*(.+)", content)
    vuln      = re.search(r"Vulnerable Contract\s*:\s*(.+)", content)
    attack_tx = re.search(r"Attack Tx\s*:\s*(.+)", content)

    return {
        "exploit_name":        path.stem.replace("_exp", ""),
        "source":              "DeFiHackLabs-Protocol",
        "date":                path.parts[-2],
        "total_lost":          lost.group(1).strip()      if lost      else "unknown",
        "attacker":            attacker.group(1).strip()  if attacker  else "unknown",
        "vulnerable_contract": vuln.group(1).strip()      if vuln      else "unknown",
        "attack_tx":           attack_tx.group(1).strip() if attack_tx else "unknown",
        "chain":               detect_chain(content),
        "code":                content,
    }


# ---------------------------------------------------------------------------
# Embedding with rate-limit retry
# ---------------------------------------------------------------------------

def embed_batch(texts: list) -> list:
    truncated = [t[:CODE_TRUNCATE] for t in texts]
    for attempt in range(6):
        try:
            response = openai_client.embeddings.create(input=truncated, model=EMBED_MODEL)
            return [item.embedding for item in response.data]
        except Exception as e:
            if "429" in str(e):
                wait = 10 * (2 ** attempt)
                print(f"  [~] Rate limited. Waiting {wait}s (retry {attempt+1}/6)...")
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("Max retries exceeded on embedding batch")


# ---------------------------------------------------------------------------
# Main indexing loop
# ---------------------------------------------------------------------------

def index_all(pattern: str = "datasets-protocol-exploit/src/test/**/*.sol"):
    setup_collection()

    files = glob.glob(pattern, recursive=True)
    skip_stems = {"Exploit-template", "Exploit-template_new", "RPCS_alive_test"}
    files = [f for f in files if Path(f).stem not in skip_stems]
    total = len(files)
    print(f"[*] Found {total} protocol exploit files\n")

    indexed = 0
    failed  = 0

    for batch_start in range(0, total, BATCH_SIZE):
        batch_files = files[batch_start : batch_start + BATCH_SIZE]
        payloads    = []

        for f in batch_files:
            try:
                payloads.append(parse_sol_file(f))
            except Exception as e:
                print(f"  [!] Parse failed {f}: {e}")
                failed += 1

        if not payloads:
            continue

        try:
            vectors = embed_batch([p["code"] for p in payloads])
        except Exception as e:
            print(f"  [!] Embedding batch failed: {e}")
            failed += len(payloads)
            time.sleep(2)
            continue

        points = [
            PointStruct(id=str(uuid.uuid4()), vector=vec, payload=pay)
            for vec, pay in zip(vectors, payloads)
        ]

        try:
            qdrant.upsert(collection_name=COLLECTION, points=points)
            indexed += len(points)
            for p in payloads:
                print(f"  [+] {p['exploit_name']} ({p['date']}) [{p['chain']}]")
        except Exception as e:
            print(f"  [!] Qdrant upsert failed: {e}")
            failed += len(points)

        time.sleep(1.5)

    print(f"\n[Done] Indexed: {indexed}  Failed: {failed}")
    print(f"[*] Qdrant URL: {os.getenv('QDRANT_URL', 'localhost:6333')}")


if __name__ == "__main__":
    index_all()
