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
SIM_THRESHOLD = 0.60   # skip GPT-4o if top similarity below this
CONF_THRESHOLD = 60    # treat as safe if model confidence below this


# ---------------------------------------------------------------------------
# RAG helpers
# ---------------------------------------------------------------------------

def embed(text: str) -> list[float]:
    text = text[:CODE_TRUNCATE]
    response = openai_client.embeddings.create(input=text, model=EMBED_MODEL)
    return response.data[0].embedding


def retrieve(contract_code: str, top_k: int = TOP_K) -> list:
    vector = embed(contract_code)
    # Fetch extra results to account for deduplication
    results = qdrant.query_points(
        collection_name=COLLECTION,
        query=vector,
        limit=top_k * 3,
        with_payload=True,
    ).points
    # Deduplicate by exploit_name, keep highest score
    seen = {}
    for r in results:
        name = r.payload.get("exploit_name", "")
        if name not in seen or r.score > seen[name].score:
            seen[name] = r
    # Return top_k unique results sorted by score
    return sorted(seen.values(), key=lambda x: x.score, reverse=True)[:top_k]


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

    top_sim = results[0].score if results else 0.0
    print(f"[*] Top similarity score: {round(top_sim, 3)}")

    if top_sim < SIM_THRESHOLD:
        print(f"[!] Similarity {round(top_sim, 3)} below threshold {SIM_THRESHOLD} — skipping GPT-4o, contract appears safe.")
        report = (
            "**Vulnerability Found:** No\n"
            "**Risk Level:** None\n"
            "**Vulnerability Type:** N/A\n"
            "**Similar Exploit Reference:** NONE\n"
            f"**Explanation:** Top similarity score ({round(top_sim, 3)}) is below the "
            f"minimum threshold ({SIM_THRESHOLD}). No sufficiently similar exploit pattern found in the database."
        )
        return report, results

    print("[*] Building prompt and calling GPT-4o...\n")
    context = build_context(results)

    prompt = f"""You are a smart contract security expert specializing in DeFi vulnerabilities.

Analyze the following Solidity contract for potential vulnerabilities.
Use the real-world exploit cases below (retrieved from DeFiHackLabs) as reference — these are the most similar past attacks based on semantic similarity.

## Similar Real-World Exploit Cases from DeFiHackLabs:
{context}

## Contract to Analyze:
{contract_code}

## Critical instructions before answering:
1. The exploit cases show HOW past vulnerabilities worked. Your job is to determine if THIS contract has the same UNMITIGATED flaw — not just a similar structure.
2. Actively check for these mitigations. If any are correctly implemented, they PREVENT exploitation:
   - ReentrancyGuard modifier or Checks-Effects-Interactions (state update before external call)
   - TWAP / time-weighted average price oracle (resistant to single-block manipulation)
   - onlyOwner / role-based access control on sensitive functions
   - Solidity 0.8+ built-in overflow protection or SafeMath
3. Structural similarity to an exploit is NOT sufficient. The contract must have the same exploitable flaw WITH NO mitigation present.
4. Include a CONFIDENCE score (0-100) reflecting how certain you are a real exploitable vulnerability exists with no mitigation.

## Provide a structured security report with the following sections:

**Vulnerability Found:** Yes / No
**Risk Level:** Critical / High / Medium / Low / None
**Vulnerability Type:** (e.g. Reentrancy, Flash Loan, Price Manipulation, Access Control, etc.)
**Confidence:** (0-100 — certainty that a real exploitable vulnerability exists with no mitigation present)
**Similar Exploit Reference:** (which exploit case above is most relevant and why)
**Explanation:** (describe the exact vulnerability and how an attacker could exploit it step-by-step)
**Recommendation:** Show the FIXED version of the vulnerable code as a complete Solidity snippet. Do not give bullet points — write the corrected contract code directly with inline comments explaining each fix.
"""

    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=3000,
    )
    report = response.choices[0].message.content

    # Confidence gate — override to safe if model isn't confident enough
    conf = 50
    for line in report.splitlines():
        if line.strip().lower().startswith("**confidence:**"):
            try:
                conf = int(line.split(":", 1)[1].strip().split()[0])
            except (ValueError, IndexError):
                pass
    if conf < CONF_THRESHOLD:
        print(f"[!] Model confidence {conf} below threshold {CONF_THRESHOLD} — overriding to No vulnerability.")
        report = report.replace("**Vulnerability Found:** Yes", "**Vulnerability Found:** No (low confidence override)")

    return report, results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

SAMPLE_CONTRACT = """
// https://tornado.cash
/*
 * d888888P                                           dP              a88888b.                   dP
 *    88                                              88             d8'   `88                   88
 *    88    .d8888b. 88d888b. 88d888b. .d8888b. .d888b88 .d8888b.    88        .d8888b. .d8888b. 88d888b.
 *    88    88'  `88 88'  `88 88'  `88 88'  `88 88'  `88 88'  `88    88        88'  `88 Y8ooooo. 88'  `88
 *    88    88.  .88 88       88    88 88.  .88 88.  .88 88.  .88 dP Y8.   .88 88.  .88       88 88    88
 *    dP    `88888P' dP       dP    dP `88888P8 `88888P8 `88888P' 88  Y88888P' `88888P8 `88888P' dP    dP
 * ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
 */

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {MerkleTreeWithHistory} from "./MerkleTreeWithHistory.sol";
import {ReentrancyGuard} from "./ReentrancyGuard.sol";
import {MockToken} from "./MockToken.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

interface IVerifier {
  function verifyProof(
    uint256[2] calldata _pA,
    uint256[2][2] calldata _pB,
    uint256[2] calldata _pC,
    uint256[26] calldata _pubSignals
  )
    external
    view
    returns (bool);
}

contract Zringotts is MerkleTreeWithHistory, ReentrancyGuard {
  IVerifier public immutable verifier;

  MockToken public weth;
  MockToken public usdc;

  struct State {
    int256 weth_deposit_amount;
    int256 weth_borrow_amount;
    int256 usdc_deposit_amount;
    int256 usdc_borrow_amount;
  }

  State public state;

  struct Liquidated {
    uint256 liq_price;
    uint256 timestamp;
  }

  uint256 public constant LIQUIDATED_ARRAY_NUMBER = 10;
  Liquidated[] public liquidated_array;

  mapping(bytes32 => bool) public nullifierHashes;
  // we store all commitments just to prevent accidental deposits with the same commitment
  mapping(bytes32 => bool) public commitments;

  event Deposit(bytes32 nullifierHash, uint256 timestamp);
  event Borrow(address to, bytes32 nullifierHash, uint256 timestamp);
  event Repay(bytes32 nullifierHash, uint256 timestamp);
  event Withdraw(address to, bytes32 nullifierHash, uint256 timestamp);
  event Claim(address to, bytes32 nullifierHash, uint256 timestamp);
  event CommitmentAdded(bytes32 indexed commitment, uint32 indexed leafIndex);

  // event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

  // /**
  //  * @dev The constructor
  //  * @param _verifier the address of SNARK verifier for this contract
  //  * @param _hasher the address of Poseidon hash contract
  //  * @param _denomination transfer amount for each deposit
  //  * @param _merkleTreeHeight the height of deposits' Merkle Tree
  //  */
  constructor(
    IVerifier _verifier,
    uint32 _merkleTreeHeight,
    MockToken _weth,
    MockToken _usdc
  )
    MerkleTreeWithHistory(_merkleTreeHeight)
  {
    verifier = _verifier;

    // Initialize liquidated array
    for (uint256 i = 0; i < LIQUIDATED_ARRAY_NUMBER; i++) {
      liquidated_array.push(Liquidated({liq_price: i + 1, timestamp: 0}));
    }

    weth = _weth;
    usdc = _usdc;
  }

  function flatten_liquidated_array() public view returns (uint256[] memory) {
    uint256[] memory output = new uint256[](LIQUIDATED_ARRAY_NUMBER * 2);
    for (uint256 i = 0; i < LIQUIDATED_ARRAY_NUMBER; i++) {
      output[2 * i] = liquidated_array[i].liq_price;
      output[2 * i + 1] = liquidated_array[i].timestamp;
    }
    return output;
  }

  function update_liquidated_array(uint8 index, uint256 _liq_price, uint256 _timestamp) public {
    require(index < LIQUIDATED_ARRAY_NUMBER, "Index exceeds number of possible liquidated position buckets");
    liquidated_array[index].liq_price = _liq_price;
    liquidated_array[index].timestamp = _timestamp;
  }

  modifier isWethOrUsdc(MockToken _token) {
    require(address(_token) == address(weth) || address(_token) == address(usdc), "Token must be weth or usdc");
    _;
  }

  function constructPublicInputs(
    bytes32 _new_note_hash,
    bytes32 _root,
    uint256 _lend_token_out,
    uint256 _borrow_token_out,
    uint256 _lend_token_in,
    uint256 _borrow_token_in
  )
    public
    view
    returns (uint256[26] memory)
  {
    uint256[26] memory public_inputs;
    public_inputs[0] = uint256(_new_note_hash);
    public_inputs[1] = uint256(_root);
    // Indices 2-11: liq_price[0-9]
    for (uint256 i = 0; i < 10; i++) {
      public_inputs[2 + i] = liquidated_array[i].liq_price;
    }
    // Indices 12-21: liq_timestamp[0-9]
    for (uint256 i = 0; i < 10; i++) {
      public_inputs[12 + i] = liquidated_array[i].timestamp;
    }
    public_inputs[22] = _lend_token_out;
    public_inputs[23] = _borrow_token_out;
    public_inputs[24] = _lend_token_in;
    public_inputs[25] = _borrow_token_in;
    return public_inputs;
  }

  function deposit(
    bytes32 _new_note_hash,
    bytes32,
    uint256 _new_timestamp,
    bytes32 _root,
    bytes32 _old_nullifier,
    uint256[2] calldata _pA,
    uint256[2][2] calldata _pB,
    uint256[2] calldata _pC,
    uint256 _lend_amt,
    MockToken _lend_token
  )
    external
    payable
    nonReentrant
    isWethOrUsdc(_lend_token)
  {
    // TODO: check _new_will_liq_price is valid from some price oracle

    // Check valid timestamp
    require(
      _new_timestamp > block.timestamp - 5 minutes, "Invalid timestamp, must be within 5 minutes of proof generation"
    );
    require(_new_timestamp <= block.timestamp, "Invalid timestamp, must be in the past");

    // Transfer token from user to contract
    require(_lend_token.transferFrom(msg.sender, address(this), _lend_amt), "Token lend failed");

    // Verify proof
    uint256[26] memory public_inputs = constructPublicInputs(
      _new_note_hash,
      _root,
      0, // lend_token_out
      0, // borrow_token_out
      _lend_amt, // lend_token_in
      0 // borrow_token_in
    );
    require(verifier.verifyProof(_pA, _pB, _pC, public_inputs), "Invalid deposit proof");

    // New note commitment add to tree
    require(!commitments[_new_note_hash], "The commitment has been submitted");
    uint32 inserted_index = _insert(_new_note_hash);
    commitments[_new_note_hash] = true;

    // if old nullifier is not zero (new note), check if it is spent
    if (_old_nullifier != bytes32(0)) {
      // Check valid root
      require(isKnownRoot(_root), "Cannot find your merkle root");

      // Check old note nullifier
      require(!nullifierHashes[_old_nullifier], "The note has been already spent");
      nullifierHashes[_old_nullifier] = true;
    }

    if (address(_lend_token) == address(weth)) {
      state.weth_deposit_amount += int256(_lend_amt);
    } else {
      state.usdc_deposit_amount += int256(_lend_amt);
    }

    emit CommitmentAdded(_new_note_hash, inserted_index);
    emit Deposit(_old_nullifier, _new_timestamp);
  }

  function borrow(
    bytes32 _new_note_hash,
    bytes32,
    uint256 _new_timestamp,
    bytes32 _root,
    bytes32 _old_nullifier,
    uint256[2] calldata _pA,
    uint256[2][2] calldata _pB,
    uint256[2] calldata _pC,
    uint256 _borrow_amt,
    MockToken _borrow_token,
    address _to
  )
    external
    payable
    nonReentrant
    isWethOrUsdc(_borrow_token)
  {
    // TODO: check _new_will_liq_price is valid from some price oracle

    // Check valid timestamp
    require(
      _new_timestamp > block.timestamp - 5 minutes, "Invalid timestamp, must be within 5 minutes of proof generation"
    );
    require(_new_timestamp <= block.timestamp, "Invalid timestamp, must be in the past");

    _borrow_token.transfer(_to, _borrow_amt);

    // Verify proof
    uint256[26] memory public_inputs = constructPublicInputs(
      _new_note_hash,
      _root,
      0, // lend_token_out
      0, // borrow_token_out
      0, // lend_token_in
      _borrow_amt // borrow_token_in
    );
    require(verifier.verifyProof(_pA, _pB, _pC, public_inputs), "Invalid borrow proof");

    // New note commitment add to tree
    require(!commitments[_new_note_hash], "The commitment has been submitted");
    uint32 inserted_index = _insert(_new_note_hash);
    commitments[_new_note_hash] = true;

    // Check valid root
    require(isKnownRoot(_root), "Cannot find your merkle root");

    // Check old nullifier is not zero
    require(_old_nullifier != bytes32(0), "Old nullifier must not be zero");

    // Check old note nullifier
    require(!nullifierHashes[_old_nullifier], "The note has been already spent");
    nullifierHashes[_old_nullifier] = true;

    if (address(_borrow_token) == address(weth)) {
      state.weth_borrow_amount += int256(_borrow_amt);
    } else {
      state.usdc_borrow_amount += int256(_borrow_amt);
    }

    emit CommitmentAdded(_new_note_hash, inserted_index);
    emit Borrow(_to, _old_nullifier, _new_timestamp);
  }

  function repay(
    bytes32 _new_note_hash,
    bytes32,
    uint256 _new_timestamp,
    bytes32 _root,
    bytes32 _old_nullifier,
    uint256[2] calldata _pA,
    uint256[2][2] calldata _pB,
    uint256[2] calldata _pC,
    uint256 _repay_amt,
    MockToken _repay_token
  )
    external
    payable
    nonReentrant
    isWethOrUsdc(_repay_token)
  {
    // TODO: check _new_will_liq_price is valid from some price oracle

    // Check valid timestamp
    require(
      _new_timestamp > block.timestamp - 5 minutes, "Invalid timestamp, must be within 5 minutes of proof generation"
    );
    require(_new_timestamp <= block.timestamp, "Invalid timestamp, must be in the past");

    _repay_token.transferFrom(msg.sender, address(this), _repay_amt);

    // Verify proof
    uint256[26] memory public_inputs = constructPublicInputs(
      _new_note_hash,
      _root,
      0, // lend_token_out
      _repay_amt, // borrow_token_out (repaying borrow)
      0, // lend_token_in
      0 // borrow_token_in
    );
    require(verifier.verifyProof(_pA, _pB, _pC, public_inputs), "Invalid repay proof");

    // New note commitment add to tree
    require(!commitments[_new_note_hash], "The commitment has been submitted");
    uint32 inserted_index = _insert(_new_note_hash);
    commitments[_new_note_hash] = true;

    // Check valid root
    require(isKnownRoot(_root), "Cannot find your merkle root");

    // Check old nullifier is not zero
    require(_old_nullifier != bytes32(0), "Old nullifier must not be zero");

    // Check old note nullifier
    require(!nullifierHashes[_old_nullifier], "The note has been already spent");
    nullifierHashes[_old_nullifier] = true;

    if (address(_repay_token) == address(weth)) {
      state.weth_borrow_amount -= int256(_repay_amt);
    } else {
      state.usdc_borrow_amount -= int256(_repay_amt);
    }

    emit CommitmentAdded(_new_note_hash, inserted_index);
    emit Repay(_old_nullifier, _new_timestamp);
  }

  function withdraw(
    bytes32 _new_note_hash,
    bytes32,
    uint256 _new_timestamp,
    bytes32 _root,
    bytes32 _old_nullifier,
    uint256[2] calldata _pA,
    uint256[2][2] calldata _pB,
    uint256[2] calldata _pC,
    uint256 _withdraw_amt,
    MockToken _withdraw_token,
    address _to
  )
    external
    payable
    nonReentrant
    isWethOrUsdc(_withdraw_token)
  {
    // TODO: check _new_will_liq_price is valid from some price oracle

    // Check valid timestamp
    require(
      _new_timestamp > block.timestamp - 5 minutes, "Invalid timestamp, must be within 5 minutes of proof generation"
    );
    require(_new_timestamp <= block.timestamp, "Invalid timestamp, must be in the past");

    _withdraw_token.transfer(_to, _withdraw_amt);

    // Verify proof
    uint256[26] memory public_inputs = constructPublicInputs(
      _new_note_hash,
      _root,
      _withdraw_amt, // lend_token_out (withdrawing deposit)
      0, // borrow_token_out
      0, // lend_token_in
      0 // borrow_token_in
    );
    require(verifier.verifyProof(_pA, _pB, _pC, public_inputs), "Invalid withdraw proof");

    // New note commitment add to tree
    require(!commitments[_new_note_hash], "The commitment has been submitted");
    uint32 inserted_index = _insert(_new_note_hash);
    commitments[_new_note_hash] = true;

    // Check valid root
    require(isKnownRoot(_root), "Cannot find your merkle root");

    // Check old nullifier is not zero
    require(_old_nullifier != bytes32(0), "Old nullifier must not be zero");

    // Check old note nullifier
    require(!nullifierHashes[_old_nullifier], "The note has been already spent");
    nullifierHashes[_old_nullifier] = true;

    if (address(_withdraw_token) == address(weth)) {
      state.weth_deposit_amount -= int256(_withdraw_amt);
    } else {
      state.usdc_deposit_amount -= int256(_withdraw_amt);
    }

    emit CommitmentAdded(_new_note_hash, inserted_index);
    emit Withdraw(_to, _old_nullifier, _new_timestamp);
  }

  function claim(
    bytes32 _new_note_hash,
    bytes32,
    uint256 _new_timestamp,
    bytes32 _root,
    bytes32 _old_nullifier,
    uint256[2] calldata _pA,
    uint256[2][2] calldata _pB,
    uint256[2] calldata _pC,
    uint256 _claim_amt,
    MockToken _claim_token,
    address _to
  )
    external
    payable
    nonReentrant
    isWethOrUsdc(_claim_token)
  {
    // TODO: check _new_will_liq_price is valid from some price oracle

    // Check valid timestamp
    require(
      _new_timestamp > block.timestamp - 5 minutes, "Invalid timestamp, must be within 5 minutes of proof generation"
    );
    require(_new_timestamp <= block.timestamp, "Invalid timestamp, must be in the past");

    _claim_token.transfer(_to, _claim_amt);

    // Verify proof
    uint256[26] memory public_inputs = constructPublicInputs(
      _new_note_hash,
      _root,
      0, // lend_token_out
      _claim_amt, // borrow_token_out (claiming liquidation)
      0, // lend_token_in
      0 // borrow_token_in
    );
    require(verifier.verifyProof(_pA, _pB, _pC, public_inputs), "Invalid claim proof");

    // New note commitment add to tree
    require(!commitments[_new_note_hash], "The commitment has been submitted");
    uint32 inserted_index = _insert(_new_note_hash);
    commitments[_new_note_hash] = true;

    // Check valid root
    require(isKnownRoot(_root), "Cannot find your merkle root");

    // Check old nullifier is not zero
    require(_old_nullifier != bytes32(0), "Old nullifier must not be zero");

    // Check old note nullifier
    require(!nullifierHashes[_old_nullifier], "The note has been already spent");
    nullifierHashes[_old_nullifier] = true;

    emit CommitmentAdded(_new_note_hash, inserted_index);
    emit Withdraw(_to, _old_nullifier, _new_timestamp);
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
