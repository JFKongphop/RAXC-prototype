"""
RAXC Analyzer — RAG-powered smart contract vulnerability scanner.
Usage:
  python3 analyze.py                        # uses built-in sample contract
  python3 analyze.py path/to/contract.sol   # analyze a specific file
"""

import os
import re
import sys
import datetime
from pathlib import Path
from openai import OpenAI
from qdrant_client import QdrantClient
from dotenv import load_dotenv

load_dotenv()

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
qdrant = QdrantClient("localhost", port=6333)

# Collections queried during retrieval
COLL_PROTOCOLS  = "defi_protocols"   # datasets-protocol-exploit real attacks
COLL_CASES      = "defi_cases"       # DeFiVulnLabs educational patterns

EMBED_MODEL   = "text-embedding-3-small"
TOP_K         = 5     # results per collection
CODE_TRUNCATE = 6000
SIM_THRESHOLD = 0.60  # skip GPT-4o if top similarity below this
CONF_THRESHOLD = 60   # treat as safe if model confidence below this


# ---------------------------------------------------------------------------
# RAG helpers
# ---------------------------------------------------------------------------

def embed(text: str) -> list[float]:
    text = text[:CODE_TRUNCATE]
    response = openai_client.embeddings.create(input=text, model=EMBED_MODEL)
    return response.data[0].embedding


def _query_collection(vector: list, collection: str, top_k: int) -> list:
    """Query a single collection, return empty list if collection doesn't exist."""
    try:
        return qdrant.query_points(
            collection_name=collection,
            query=vector,
            limit=top_k * 2,
            with_payload=True,
        ).points
    except Exception:
        return []


def retrieve(contract_code: str, top_k: int = TOP_K) -> list:
    vector = embed(contract_code)

    # Query both collections
    raw: list = []
    raw += _query_collection(vector, COLL_PROTOCOLS, top_k)
    raw += _query_collection(vector, COLL_CASES,     top_k)

    # Deduplicate by exploit_name, keep highest score
    seen: dict = {}
    for r in raw:
        name = r.payload.get("exploit_name", "")
        if name not in seen or r.score > seen[name].score:
            seen[name] = r

    # Return top_k unique results sorted by score
    return sorted(seen.values(), key=lambda x: x.score, reverse=True)[:top_k]


def build_context(results: list) -> str:
    context = ""
    for i, r in enumerate(results):
        p = r.payload
        score  = round(r.score, 3)
        source = p.get("source", "DeFiHackLabs")
        is_real = source != "DeFiVulnLabs"

        header = f"--- Reference {i+1}: {p['exploit_name']} ({p['date']}) [similarity: {score}] [source: {source}] ---"
        chain  = f"Chain: {p['chain']}"

        if is_real:
            # Real exploit — show actual loss and tx
            attack_tx = p.get('attack_tx', 'unknown')
            tx_line   = f"Attack Tx: {attack_tx}"
            lost_line = f"Total Lost: {p.get('total_lost', 'unknown')}"
            type_line = ""
        else:
            # Educational pattern — no real tx or loss
            tx_line   = "Attack Tx: N/A (educational pattern — no on-chain incident)"
            lost_line = "Total Lost: N/A"
            type_line = f"Vulnerability Type: {p.get('vuln_type', 'unknown')}\n"

        context += f"""
{header}
{chain}
{lost_line}
{tx_line}
{type_line}Vulnerable Contract: {p.get('vulnerable_contract', 'unknown')}
Code Snippet:
{p['code'][:1500]}
"""
    return context


# ---------------------------------------------------------------------------
# Function-level exploit matching
# ---------------------------------------------------------------------------

def extract_functions(code: str) -> dict:
    """Extract individual Solidity function bodies keyed by name."""
    functions = {}
    for m in re.finditer(r'\bfunction\s+(\w+)\s*\(', code):
        name = m.group(1)
        start = m.start()
        brace_pos = code.find('{', m.end())
        if brace_pos == -1:
            continue
        depth = 0
        end = brace_pos
        for i in range(brace_pos, len(code)):
            if code[i] == '{':
                depth += 1
            elif code[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        functions[name] = code[start:end]
    return functions


def match_functions(contract_code: str, top_k: int = 3) -> list:
    """Embed each function individually and find its top matching exploit cases."""
    functions = extract_functions(contract_code)
    results = []
    for func_name, func_body in functions.items():
        vector = embed(func_body)
        raw = []
        raw += _query_collection(vector, COLL_PROTOCOLS, top_k)
        raw += _query_collection(vector, COLL_CASES,     top_k)
        seen = {}
        for r in raw:
            name = r.payload.get("exploit_name", "")
            if name not in seen or r.score > seen[name].score:
                seen[name] = r
        top = sorted(seen.values(), key=lambda x: x.score, reverse=True)[:top_k]
        results.append({"function": func_name, "matches": top})
    return results


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(contract_code: str) -> tuple:
    print(f"[*] Retrieving top {TOP_K} results from defi_protocols + defi_cases...")
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
Use the reference cases below as context — retrieved from DeFiHackLabs (real protocol attacks) and DeFiVulnLabs (educational vulnerability patterns).

## Similar Reference Cases (DeFiHackLabs real exploits + DeFiVulnLabs educational patterns):
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
5. For EXPLOIT_TX in your report: only cite the exact Attack Tx URLs present in the reference cases above. If a reference shows "N/A" or no real tx, write N/A. Do NOT fabricate or invent transaction hashes.

## Provide a structured security report with the following sections:

**Vulnerability Found:** Yes / No
**Risk Level:** Critical / High / Medium / Low / None
**Vulnerability Type:** (e.g. Reentrancy, Flash Loan, Price Manipulation, Access Control, etc.)
**Confidence:** (0-100 — certainty that a real exploitable vulnerability exists with no mitigation present)
**Similar Exploit Reference:** (which exploit case above is most relevant and why)
**Explanation:** (describe the exact vulnerability and how an attacker could exploit it step-by-step)
**Recommendation:**
Separate each distinct issue or improvement into its own labeled case (A, B, C, ...). For each case:
- State the problem in one sentence.
- Show ONLY the one affected function rewritten in full — do NOT include contract declaration, constructor, imports, structs, or any other functions.
- Every line of the function must be written out completely — the words "existing code", "existing logic", "..." and any placeholder comments are FORBIDDEN.
- Add an inline comment on every line you changed explaining what was fixed and why.
- If a vulnerability was found: each case must directly correspond to one finding named in the Explanation section.
- If no vulnerability was found: each case must apply a concrete proactive improvement (e.g. access control, input validation, oracle integration, checks-effects-interactions) to one specific sensitive function.
- You MUST write ALL cases completely. Do NOT summarize, skip, or abbreviate any case. Do NOT end with a generic note like "apply similar changes elsewhere" — write each case in full.
"""

    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=8000,
    )
    report = response.choices[0].message.content

    # Confidence gate — override to safe if model isn't confident enough
    conf = 50
    conf_match = re.search(r'\*\*confidence[^0-9\n]*?(\d+)', report, re.IGNORECASE)
    if conf_match:
        conf = int(conf_match.group(1))
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

def _sim_badge(score: float) -> str:
    """Return a text badge for a similarity score."""
    if score >= 0.65:
        return "🔴 HIGH"
    elif score >= 0.55:
        return "🟡 MED"
    else:
        return "🟢 LOW"


def _parse_report_fields(report: str) -> dict:
    """Extract structured fields from the GPT-4o report text."""
    fields = {"vuln_found": "Unknown", "risk_level": "Unknown", "vuln_type": "N/A", "confidence": "?"}
    for line in report.splitlines():
        l = line.strip().lower()
        if l.startswith("**vulnerability found:**"):
            fields["vuln_found"] = line.split(":", 1)[1].strip().strip("*").strip()
        elif l.startswith("**risk level:**"):
            fields["risk_level"] = line.split(":", 1)[1].strip().strip("*").strip()
        elif l.startswith("**vulnerability type:**"):
            fields["vuln_type"] = line.split(":", 1)[1].strip().strip("*").strip()
        elif l.startswith("**confidence:**"):
            try:
                fields["confidence"] = int(line.split(":", 1)[1].strip().split()[0].strip("*"))
            except (ValueError, IndexError):
                pass
    return fields


def _verdict_banner(fields: dict) -> list:
    """Build a prominent verdict banner for the top of the report."""
    vuln = fields["vuln_found"].lower()
    risk = fields["risk_level"].lower()
    conf = fields["confidence"]

    if "yes" in vuln:
        if "critical" in risk:
            icon, bar = "🚨", "CRITICAL VULNERABILITY FOUND"
        elif "high" in risk:
            icon, bar = "🔴", "HIGH RISK VULNERABILITY FOUND"
        elif "medium" in risk:
            icon, bar = "🟠", "MEDIUM RISK VULNERABILITY FOUND"
        else:
            icon, bar = "🟡", "LOW RISK VULNERABILITY FOUND"
    else:
        icon, bar = "✅", "NO EXPLOITABLE VULNERABILITY FOUND"

    return [
        f"> ## {icon} {bar}",
        f"> **Risk Level:** {fields['risk_level']}  |  **Type:** {fields['vuln_type']}  |  **Confidence:** {conf}/100",
        "",
    ]


def save_markdown(report: str, results: list, contract_name: str = "contract", func_matches: list = None) -> str:
    """Save the report as a clean markdown file and return the path."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    filepath = out_dir / f"RAXC_{contract_name}_{timestamp}.md"

    fields = _parse_report_fields(report)

    lines = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines.append("# RAXC Security Report")
    lines.append(f"> **Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Verdict banner ───────────────────────────────────────────────────────
    lines += _verdict_banner(fields)
    lines.append("---")
    lines.append("")

    # ── Top similar exploits ─────────────────────────────────────────────────
    lines.append("## Top Similar Exploit References")
    lines.append("")
    lines.append("")
    lines.append("| # | Exploit | Date | Chain | Total Lost | Similarity |")
    lines.append("|---|---------|------|-------|------------|------------|")
    for i, r in enumerate(results):
        p = r.payload
        score = round(r.score, 3)
        exploit_name = p['exploit_name']
        tx = p.get('attack_tx', 'unknown')
        name_cell = f"[{exploit_name}]({tx})" if tx.startswith("http") else exploit_name
        badge = _sim_badge(score)
        lines.append(f"| {i+1} | **{name_cell}** | {p['date']} | {p['chain']} | {p.get('total_lost', 'unknown')} | {score} {badge} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Function exploit matching ─────────────────────────────────────────────
    if func_matches:
        lines.append("## Function-Level Exploit Matching")
        lines.append("")
        lines.append("*Each contract function embedded and matched independently against the exploit database.*")
        lines.append("")
        lines.append("| Similarity | Meaning |")
        lines.append("|-----------|---------|")
        lines.append("| 🔴 ≥ 0.65 | High — strong structural match to known exploit |")
        lines.append("| 🟡 0.55–0.65 | Medium — partial overlap with exploit pattern |")
        lines.append("| 🟢 < 0.55 | Low — weak or incidental similarity |")
        lines.append("")
        for fm in func_matches:
            top_score = fm["matches"][0].score if fm["matches"] else 0
            badge = _sim_badge(top_score)
            lines.append(f"### `{fm['function']}` {badge}")
            lines.append("")
            lines.append("| # | Exploit | Date | Chain | Total Lost | Similarity |")
            lines.append("|---|---------|------|-------|------------|------------|")
            for j, r in enumerate(fm["matches"]):
                p = r.payload
                score = round(r.score, 3)
                tx = p.get('attack_tx', 'unknown')
                name = p['exploit_name']
                name_cell = f"[{name}]({tx})" if tx.startswith("http") else name
                lines.append(f"| {j+1} | **{name_cell}** | {p['date']} | {p['chain']} | {p.get('total_lost','N/A')} | {score} {_sim_badge(score)} |")
            lines.append("")
        lines.append("---")
        lines.append("")

    # ── Analysis & Recommendation ─────────────────────────────────────────────
    lines.append("## Analysis & Recommendation")
    lines.append("")
    lines.append(report)
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("> *Powered by RAXC — RAG-based smart contract vulnerability scanner*  ")
    lines.append("> *Embeddings: OpenAI text-embedding-3-small · LLM: GPT-4o · Vector DB: Qdrant*")

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

    print("[*] Running function-level exploit matching...")
    func_matches = match_functions(contract_code)

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
    print("FUNCTION EXPLOIT MATCHING")
    print("=" * 60)
    for fm in func_matches:
        print(f"\n  [{fm['function']}]")
        for j, r in enumerate(fm["matches"]):
            p = r.payload
            src = p.get("source", "DeFiHackLabs")
            print(f"    #{j+1}  {p['exploit_name']:<30}  score={round(r.score, 3)}  chain={p['chain']}  lost={p.get('total_lost','N/A')}  [{src}]")
    print()

    print("=" * 60)
    print("RAXC SECURITY REPORT")
    print("=" * 60)
    print(report)
    print("=" * 60)

    # Save markdown report
    contract_name = Path(sys.argv[1]).stem if len(sys.argv) > 1 else "sample"
    md_path = save_markdown(report, results, contract_name, func_matches=func_matches)
    print(f"\n[*] Report saved → {md_path}")