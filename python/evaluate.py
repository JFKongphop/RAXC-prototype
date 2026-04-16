"""
RAXC Evaluator — Compare baseline RAG vs optimized configurations.
Usage:
  python3 evaluate.py           # run full benchmark
  python3 evaluate.py --quick   # run on 5 contracts only (faster)

Metrics measured:
  - Precision / Recall / F1 (vulnerability detection)
  - Hallucination rate (fabricated exploit references)
  - Avg similarity score (retrieval quality)
  - Specificity rate (reports with real exploit tx link)
"""

import os
import re
import sys
import json
import time
import datetime
from pathlib import Path
from openai import OpenAI
from qdrant_client import QdrantClient
from dotenv import load_dotenv

load_dotenv()

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
qdrant = QdrantClient("localhost", port=6333)

COLL_PROTOCOLS = "defi_protocols"   # real protocol exploit POCs
COLL_CASES     = "defi_cases"       # DeFiVulnLabs educational patterns
CODE_TRUNCATE = 6000
TOP_K = 5

# ---------------------------------------------------------------------------
# Ground-truth test set
# Each entry: contract code, expected vulnerability (None = safe)
# ---------------------------------------------------------------------------

TEST_SET = [
    {
        "name": "reentrancy_basic",
        "expected_vuln": True,
        "expected_type": "Reentrancy",
        "code": """
pragma solidity ^0.8.0;
contract VulnerableVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}"""
    },
    {
        "name": "price_manipulation",
        "expected_vuln": True,
        "expected_type": "Price Manipulation",
        "code": """
pragma solidity ^0.8.0;
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}
contract VulnerableLending {
    IUniswapV2Pair public pair;
    mapping(address => uint256) public collateral;
    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);
    }
    function borrow(uint256 amount) external {
        uint256 val = (collateral[msg.sender] * getPrice()) / 1e18;
        require(amount <= (val * 80) / 100);
        payable(msg.sender).transfer(amount);
    }
}"""
    },
    {
        "name": "access_control",
        "expected_vuln": True,
        "expected_type": "Access Control",
        "code": """
pragma solidity ^0.8.0;
contract VulnerableOwnable {
    address public owner;
    mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    function setOwner(address newOwner) external {
        // Missing onlyOwner check — anyone can call this
        owner = newOwner;
    }
    function drain() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}"""
    },
    {
        "name": "integer_overflow",
        "expected_vuln": True,
        "expected_type": "Integer Overflow",
        "code": """
pragma solidity ^0.6.0;
contract VulnerableToken {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) external {
        // No SafeMath — overflow possible in Solidity 0.6
        require(balances[msg.sender] - amount >= 0);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}"""
    },
    {
        "name": "flash_loan_attack",
        "expected_vuln": True,
        "expected_type": "Flash Loan",
        "code": """
pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address) external view returns (uint256); }
contract VulnerableRewards {
    IERC20 public token;
    mapping(address => uint256) public lastSnapshot;
    function snapshot() external {
        lastSnapshot[msg.sender] = token.balanceOf(msg.sender);
    }
    function claimReward() external {
        uint256 bal = lastSnapshot[msg.sender];
        // Attacker can snapshot after flash-borrowing a huge balance
        payable(msg.sender).transfer(bal / 100);
    }
}"""
    },
    {
        "name": "safe_reentrancy_guard",
        "expected_vuln": False,
        "expected_type": None,
        "code": """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}"""
    },
    {
        "name": "safe_twap_oracle",
        "expected_vuln": False,
        "expected_type": None,
        "code": """
pragma solidity ^0.8.0;
interface ITWAPOracle { function getPrice() external view returns (uint256); }
contract SafeLending {
    ITWAPOracle public oracle;
    mapping(address => uint256) public collateral;
    constructor(address _oracle) { oracle = ITWAPOracle(_oracle); }
    function borrow(uint256 amount) external {
        uint256 price = oracle.getPrice(); // TWAP — manipulation resistant
        uint256 val = (collateral[msg.sender] * price) / 1e18;
        require(amount <= (val * 80) / 100, "Undercollateralized");
        payable(msg.sender).transfer(amount);
    }
}"""
    },
    {
        "name": "safe_access_control",
        "expected_vuln": False,
        "expected_type": None,
        "code": """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
contract SafeOwnable is Ownable {
    function drain() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
}"""
    },
    {
        "name": "delegatecall_vuln",
        "expected_vuln": True,
        "expected_type": "Delegatecall",
        "code": """
pragma solidity ^0.8.0;
contract VulnerableProxy {
    address public implementation;
    address public owner;
    constructor(address _impl) {
        implementation = _impl;
        owner = msg.sender;
    }
    fallback() external payable {
        // Delegatecall shares storage — attacker can overwrite owner
        (bool ok,) = implementation.delegatecall(msg.data);
        require(ok);
    }
}"""
    },
    {
        "name": "safe_checks_effects_interactions",
        "expected_vuln": False,
        "expected_type": None,
        "code": """
pragma solidity ^0.8.0;
contract SafeVaultCEI {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;   // Effect before interaction
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}"""
    },
]

# ---------------------------------------------------------------------------
# Embedding helpers
# ---------------------------------------------------------------------------

def embed_openai(text: str) -> list[float]:
    text = text[:CODE_TRUNCATE]
    resp = openai_client.embeddings.create(input=text, model="text-embedding-3-small")
    return resp.data[0].embedding


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def _query_collection(vector: list, collection: str, top_k: int) -> list:
    try:
        return qdrant.query_points(
            collection_name=collection,
            query=vector,
            limit=top_k * 2,
            with_payload=True,
        ).points
    except Exception:
        return []


def retrieve(vector: list, deduplicate: bool = True, collections: list = None) -> list:
    if collections is None:
        collections = [COLL_PROTOCOLS, COLL_CASES]
    raw: list = []
    for coll in collections:
        raw += _query_collection(vector, coll, TOP_K)
    if deduplicate:
        seen: dict = {}
        for r in raw:
            name = r.payload.get("exploit_name", "")
            if name not in seen or r.score > seen[name].score:
                seen[name] = r
        return sorted(seen.values(), key=lambda x: x.score, reverse=True)[:TOP_K]
    return sorted(raw, key=lambda x: x.score, reverse=True)[:TOP_K]


# ---------------------------------------------------------------------------
# GPT-4o analysis
# ---------------------------------------------------------------------------

def analyze(contract_code: str, results: list) -> str:
    context = ""
    for i, r in enumerate(results):
        p = r.payload
        source   = p.get("source", "DeFiHackLabs")
        is_real  = source != "DeFiVulnLabs"
        tx_line  = f"Attack Tx: {p.get('attack_tx', 'unknown')}" if is_real else "Attack Tx: N/A (educational pattern — no on-chain incident)"
        lost_line = f"Lost: {p.get('total_lost', 'unknown')}" if is_real else "Lost: N/A"
        context += f"""
--- Reference {i+1}: {p['exploit_name']} ({p['date']}) [similarity: {round(r.score,3)}] [source: {source}] ---
Chain: {p['chain']} | {lost_line}
{tx_line}
Code:
{p['code'][:800]}
"""
    prompt = f"""You are a smart contract security expert.
Analyze this Solidity contract using the reference cases below (DeFiHackLabs real exploits + DeFiVulnLabs educational patterns).

## Reference Cases:
{context}

## Contract:
{contract_code}

## Critical instructions before answering:
1. The exploit cases show HOW past vulnerabilities worked. Your job is to determine if THIS contract has the same UNMITIGATED flaw — not just a similar structure.
2. Actively check for these mitigations. If any are correctly implemented, they PREVENT exploitation and you MUST set VULN_FOUND: No:
   - ReentrancyGuard modifier or Checks-Effects-Interactions (state update before external call)
   - TWAP / time-weighted average price oracle (resistant to single-block manipulation)
   - onlyOwner / role-based access control on sensitive functions
   - Solidity 0.8+ built-in overflow protection or SafeMath
3. Structural similarity to an exploit is NOT sufficient to flag a vulnerability. The contract must have the same exploitable flaw WITH NO mitigation present.
4. For EXPLOIT_TX: only cite the exact Attack Tx URLs present in the reference cases above. If a reference shows "N/A", write NONE. Do NOT fabricate or invent transaction hashes.

## Report (answer EXACTLY in this format, no extra text):
VULN_FOUND: Yes or No
RISK_LEVEL: Critical or High or Medium or Low or None
VULN_TYPE: <one phrase>
EXPLOIT_REF: <exploit name from the list above, or NONE>
EXPLOIT_TX: <tx url from the list above, or NONE>
CONFIDENCE: <integer 0-100 — how confident are you that a real exploitable vulnerability exists with no mitigation present>
EXPLANATION: <2-3 sentences>"""
    resp = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=600,
    )
    return resp.choices[0].message.content


# ---------------------------------------------------------------------------
# Parse structured report
# ---------------------------------------------------------------------------

def parse_report(text: str) -> dict:
    def extract(key):
        m = re.search(rf"{key}:\s*(.+)", text, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    confidence_str = extract("CONFIDENCE")
    try:
        confidence = int(confidence_str)
    except (ValueError, TypeError):
        confidence = 50  # default if missing

    return {
        "vuln_found": extract("VULN_FOUND").lower() == "yes",
        "risk_level": extract("RISK_LEVEL"),
        "vuln_type": extract("VULN_TYPE"),
        "exploit_ref": extract("EXPLOIT_REF"),
        "exploit_tx": extract("EXPLOIT_TX"),
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Metrics calculation
# ---------------------------------------------------------------------------

def calc_metrics(results_list: list) -> dict:
    tp = fp = fn = tn = 0
    hallucinated = 0
    has_real_tx = 0
    similarity_scores = []

    for r in results_list:
        pred = r["parsed"]["vuln_found"]
        actual = r["expected_vuln"]
        exploit_ref = r["parsed"]["exploit_ref"]
        exploit_tx = r["parsed"]["exploit_tx"]
        top_score = r["top_similarity"]

        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and actual:
            fn += 1
        else:
            tn += 1

        # Hallucination: exploit_ref that doesn't exist in top-5
        known_names = [x["exploit_name"] for x in r["retrieved_exploits"]]
        if exploit_ref and exploit_ref.upper() != "NONE":
            ref_clean = exploit_ref.lower().strip()
            if not any(ref_clean in k.lower() for k in known_names):
                hallucinated += 1

        # Specificity: has real on-chain tx link
        if exploit_tx and exploit_tx.startswith("http"):
            has_real_tx += 1

        similarity_scores.append(top_score)

    total = len(results_list)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "total": total,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "hallucination_rate": round(hallucinated / total, 3),
        "specificity_rate": round(has_real_tx / total, 3),
        "avg_similarity": round(sum(similarity_scores) / len(similarity_scores), 3),
    }


# ---------------------------------------------------------------------------
# Run one configuration
# ---------------------------------------------------------------------------

def run_config(name: str, embed_fn, deduplicate: bool, test_cases: list,
               collections: list = None, sim_threshold: float = 0.0,
               confidence_threshold: int = 0) -> dict:
    print(f"\n{'='*55}")
    print(f"  Config: {name}")
    if sim_threshold > 0 or confidence_threshold > 0:
        print(f"  Thresholds: sim>{sim_threshold}  confidence>{confidence_threshold}")
    print(f"{'='*55}")

    results_list = []

    for tc in test_cases:
        print(f"  [{tc['name']}] ", end="", flush=True)
        try:
            vector = embed_fn(tc["code"])
            retrieved = retrieve(vector, deduplicate=deduplicate, collections=collections)

            # Optimization #1: similarity threshold gate
            top_sim = retrieved[0].score if retrieved else 0
            if sim_threshold > 0 and top_sim < sim_threshold:
                raw_report = f"VULN_FOUND: No\nRISK_LEVEL: None\nVULN_TYPE: None\nEXPLOIT_REF: NONE\nEXPLOIT_TX: NONE\nCONFIDENCE: 10\nEXPLANATION: Similarity score {round(top_sim,3)} below threshold {sim_threshold}."
            else:
                raw_report = analyze(tc["code"], retrieved)

            parsed = parse_report(raw_report)

            # Optimization #2: confidence threshold override
            if confidence_threshold > 0 and parsed["confidence"] < confidence_threshold:
                parsed["vuln_found"] = False

            retrieved_exploits = [r.payload for r in retrieved]

            results_list.append({
                "name": tc["name"],
                "expected_vuln": tc["expected_vuln"],
                "expected_type": tc.get("expected_type"),
                "parsed": parsed,
                "top_similarity": top_sim,
                "retrieved_exploits": retrieved_exploits,
                "raw_report": raw_report,
            })

            status = "✓" if parsed["vuln_found"] == tc["expected_vuln"] else "✗"
            print(f"{status}  pred={parsed['vuln_found']} actual={tc['expected_vuln']}  score={round(top_sim,3)}  conf={parsed.get('confidence','?')}")
            time.sleep(0.5)

        except Exception as e:
            print(f"ERROR: {e}")

    metrics = calc_metrics(results_list)
    return {"config": name, "metrics": metrics, "details": results_list}


# ---------------------------------------------------------------------------
# Print comparison table
# ---------------------------------------------------------------------------

def print_comparison(configs: list):
    print(f"\n{'='*75}")
    print(f"  RAXC EVALUATION RESULTS — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*75}")
    print(f"  {'Config':<30} {'F1':>6} {'Prec':>6} {'Rec':>6} {'Halluc':>8} {'Spec':>6} {'AvgSim':>8}")
    print(f"  {'-'*30} {'-'*6} {'-'*6} {'-'*6} {'-'*8} {'-'*6} {'-'*8}")
    for c in configs:
        m = c["metrics"]
        print(
            f"  {c['config']:<30} "
            f"{m['f1']:>6.3f} "
            f"{m['precision']:>6.3f} "
            f"{m['recall']:>6.3f} "
            f"{m['hallucination_rate']:>8.3f} "
            f"{m['specificity_rate']:>6.3f} "
            f"{m['avg_similarity']:>8.3f}"
        )
    print(f"{'='*75}")
    print()
    print("  Columns:")
    print("    F1           — overall vulnerability detection accuracy")
    print("    Precision    — of all flagged issues, how many are real")
    print("    Recall       — of all real issues, how many were caught")
    print("    Halluc rate  — exploit references not in top-5 (fabricated)")
    print("    Spec rate    — reports with a real on-chain tx link")
    print("    AvgSim       — average top-1 Qdrant cosine similarity score")
    print()


# ---------------------------------------------------------------------------
# Save results to JSON
# ---------------------------------------------------------------------------

def save_results(configs: list):
    out = Path("reports")
    out.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out / f"RAXC_eval_{ts}.json"
    with open(path, "w") as f:
        json.dump([{"config": c["config"], "metrics": c["metrics"]} for c in configs], f, indent=2)
    print(f"  [*] Results saved → {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    quick = "--quick" in sys.argv
    test_cases = TEST_SET[:5] if quick else TEST_SET

    print(f"\n[*] RAXC Evaluation — {len(test_cases)} contracts")
    print(f"[*] Mode: {'quick' if quick else 'full'}\n")

    configs_results = []

    # ── Baseline: OpenAI embeddings, no deduplication ─────────────────────
    configs_results.append(
        run_config(
            name="Baseline (no dedup)",
            embed_fn=embed_openai,
            deduplicate=False,
            test_cases=test_cases,
        )
    )

    # ── Optimized: OpenAI embeddings + deduplication ───────────────────────
    configs_results.append(
        run_config(
            name="Optimized (dedup)",
            embed_fn=embed_openai,
            deduplicate=True,
            test_cases=test_cases,
        )
    )

    # ── Voyage-code-2 (if VOYAGE_API_KEY is set) ──────────────────────────
    if os.getenv("VOYAGE_API_KEY"):
        try:
            import voyageai
            voyage_client = voyageai.Client(api_key=os.getenv("VOYAGE_API_KEY"))

            def embed_voyage(text: str) -> list[float]:
                text = text[:CODE_TRUNCATE]
                result = voyage_client.embed([text], model="voyage-code-2")
                return result.embeddings[0]

            configs_results.append(
                run_config(
                    name="voyage-code-2 (dedup)",
                    embed_fn=embed_voyage,
                    deduplicate=True,
                    test_cases=test_cases,
                    collections=["defi_exploits_voyage"],
                )
            )

            # ── Voyage + threshold optimizations ──────────────────────────
            configs_results.append(
                run_config(
                    name="voyage + sim>0.80 + conf>60",
                    embed_fn=embed_voyage,
                    deduplicate=True,
                    test_cases=test_cases,
                    collections=["defi_exploits_voyage"],
                    sim_threshold=0.80,
                    confidence_threshold=60,
                )
            )
        except Exception as e:
            print(f"[!] Voyage skipped: {e}")
    else:
        print("\n[~] Skipping voyage-code-2 (no VOYAGE_API_KEY in .env)")

    # ── OpenAI + threshold optimizations ──────────────────────────────────
    configs_results.append(
        run_config(
            name="OpenAI + sim>0.60 + conf>60",
            embed_fn=embed_openai,
            deduplicate=True,
            test_cases=test_cases,
            sim_threshold=0.60,
            confidence_threshold=60,
        )
    )

    print_comparison(configs_results)
    save_results(configs_results)
