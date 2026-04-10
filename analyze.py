"""
RAXC Analyzer — RAG-powered smart contract vulnerability scanner.
Usage:
  python3 analyze.py                        # uses built-in sample contract
  python3 analyze.py path/to/contract.sol   # analyze a specific file
"""

import os
import sys
import datetime
from pathlib import Path
from openai import OpenAI
from qdrant_client import QdrantClient
from dotenv import load_dotenv

load_dotenv()

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
qdrant = QdrantClient("localhost", port=6333)

COLLECTION = "defi_exploits"
EMBED_MODEL = "text-embedding-3-small"
TOP_K = 5
CODE_TRUNCATE = 6000


# ---------------------------------------------------------------------------
# RAG helpers
# ---------------------------------------------------------------------------

def embed(text: str) -> list[float]:
    text = text[:CODE_TRUNCATE]
    response = openai_client.embeddings.create(input=text, model=EMBED_MODEL)
    return response.data[0].embedding


def retrieve(contract_code: str, top_k: int = TOP_K) -> list:
    vector = embed(contract_code)
    results = qdrant.query_points(
        collection_name=COLLECTION,
        query=vector,
        limit=top_k,
        with_payload=True,
    ).points
    return results


def build_context(results: list) -> str:
    context = ""
    for i, r in enumerate(results):
        p = r.payload
        score = round(r.score, 3)
        context += f"""
--- Exploit {i+1}: {p['exploit_name']} ({p['date']}) [similarity: {score}] ---
Chain: {p['chain']}
Total Lost: {p['total_lost']}
Attack Tx: {p['attack_tx']}
Vulnerable Contract: {p['vulnerable_contract']}
Code Snippet:
{p['code'][:1500]}
"""
    return context


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(contract_code: str) -> tuple:
    print(f"[*] Retrieving {TOP_K} most similar exploits from Qdrant...")
    results = retrieve(contract_code)

    print("[*] Building prompt and calling GPT-4o...\n")
    context = build_context(results)

    prompt = f"""You are a smart contract security expert specializing in DeFi vulnerabilities.

Analyze the following Solidity contract for potential vulnerabilities.
Use the real-world exploit cases below (retrieved from DeFiHackLabs) as reference — these are the most similar past attacks based on semantic similarity.

## Similar Real-World Exploit Cases from DeFiHackLabs:
{context}

## Contract to Analyze:
{contract_code}

## Provide a structured security report with the following sections:

**Vulnerability Found:** Yes / No
**Risk Level:** Critical / High / Medium / Low / None
**Vulnerability Type:** (e.g. Reentrancy, Flash Loan, Price Manipulation, Access Control, etc.)
**Similar Exploit Reference:** (which exploit case above is most relevant and why)
**Explanation:** (describe the exact vulnerability and how an attacker could exploit it step-by-step)
**Recommendation:** Show the FIXED version of the vulnerable code as a complete Solidity snippet. Do not give bullet points — write the corrected contract code directly with inline comments explaining each fix.
"""

    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1200,
    )

    return response.choices[0].message.content, results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

SAMPLE_CONTRACT = """
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint, uint, address, bytes calldata) external;
}

// Lending protocol that uses a Uniswap V2 spot price as collateral oracle
contract VulnerableLending {
    IUniswapV2Pair public pair;
    IERC20 public token;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _pair, address _token) {
        pair = IUniswapV2Pair(_pair);
        token = IERC20(_token);
    }

    // Returns token price based on current Uniswap reserves — manipulable via flash loan
    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    function depositCollateral(uint256 amount) external {
        token.transfer(address(this), amount);
        collateral[msg.sender] += amount;
    }

    // Borrow up to 80% of collateral value at current spot price
    function borrow(uint256 borrowAmount) external {
        uint256 price = getPrice();
        uint256 collateralValue = (collateral[msg.sender] * price) / 1e18;
        require(borrowAmount <= (collateralValue * 80) / 100, "Undercollateralized");
        debt[msg.sender] += borrowAmount;
        payable(msg.sender).transfer(borrowAmount);
    }
}
"""

def save_markdown(report: str, results: list, contract_name: str = "contract") -> str:
    """Save the report as a clean markdown file and return the path."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    filepath = out_dir / f"RAXC_{contract_name}_{timestamp}.md"

    lines = []
    lines.append("# RAXC Security Report")
    lines.append(f"> Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"> Contract: `{contract_name}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Top 5 Similar Exploits (DeFiHackLabs)")
    lines.append("")
    lines.append("| # | Exploit | Date | Chain | Lost | Similarity |")
    lines.append("|---|---------|------|-------|------|------------|")
    for i, r in enumerate(results):
        p = r.payload
        score = round(r.score, 3)
        tx = p['attack_tx']
        tx_link = f"[tx]({tx})" if tx.startswith("http") else tx
        lines.append(f"| {i+1} | **{p['exploit_name']}** | {p['date']} | {p['chain']} | {p['total_lost']} | {score} |")
    lines.append("")
    lines.append("### Exploit Transaction Links")
    lines.append("")
    for i, r in enumerate(results):
        p = r.payload
        tx = p['attack_tx']
        if tx.startswith("http"):
            lines.append(f"{i+1}. [{p['exploit_name']}]({tx})")
        else:
            lines.append(f"{i+1}. {p['exploit_name']} — {tx}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Analysis")
    lines.append("")
    lines.append(report)
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("> *Powered by RAXC — RAG-based smart contract vulnerability scanner*")
    lines.append("> *Dataset: DeFiHackLabs | Embeddings: OpenAI text-embedding-3-small | LLM: GPT-4o*")

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return str(filepath)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        contract_path = sys.argv[1]
        try:
            contract_code = open(contract_path, encoding="utf-8").read()
            print(f"[*] Analyzing: {contract_path}\n")
        except FileNotFoundError:
            print(f"[!] File not found: {contract_path}")
            sys.exit(1)
    else:
        print("[*] No file specified — using built-in reentrancy sample.\n")
        contract_code = SAMPLE_CONTRACT

    report, results = analyze(contract_code)

    print("=" * 60)
    print("TOP 5 SIMILAR EXPLOITS (from DeFiHackLabs)")
    print("=" * 60)
    for i, r in enumerate(results):
        p = r.payload
        score = round(r.score, 3)
        print(f"  #{i+1}  {p['exploit_name']}")
        print(f"       Date    : {p['date']}")
        print(f"       Chain   : {p['chain']}")
        print(f"       Lost    : {p['total_lost']}")
        print(f"       Tx      : {p['attack_tx']}")
        print(f"       Score   : {score}")
        print()

    print("=" * 60)
    print("RAXC SECURITY REPORT")
    print("=" * 60)
    print(report)
    print("=" * 60)

    # Save markdown report
    contract_name = Path(sys.argv[1]).stem if len(sys.argv) > 1 else "sample"
    md_path = save_markdown(report, results, contract_name)
    print(f"\n[*] Report saved → {md_path}")
