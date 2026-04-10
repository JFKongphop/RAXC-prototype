# RAXC Demo — Run steps in order
# Usage: make <target>

# ── Step 1: Start Qdrant ────────────────────────────────────────────────────
start:
	@echo "[1] Starting Qdrant..."
	@docker start qdrant 2>/dev/null || docker run -d --name qdrant -p 6333:6333 -p 6334:6334 qdrant/qdrant
	@echo "[✓] Qdrant running → http://localhost:6333/dashboard"

# ── Step 2: Check Qdrant has data ──────────────────────────────────────────
check:
	@echo "[2] Checking indexed exploits..."
	@curl -s http://localhost:6333/collections/defi_exploits | python3 -c \
		"import sys,json; d=json.load(sys.stdin); print('[✓] Points indexed:', d['result']['points_count'])"

# ── Step 3: Re-index missing files (only if needed) ────────────────────────
index:
	@echo "[3] Indexing all exploit files..."
	/usr/bin/python3 indexer.py

# ── Step 4: Run analysis with built-in sample ──────────────────────────────
demo:
	@echo "[4] Running demo analysis..."
	/usr/bin/python3 analyze.py

# ── Step 5: Run analysis on a specific contract ────────────────────────────
# Usage: make analyze FILE=path/to/contract.sol
analyze:
	@echo "[4] Analyzing $(FILE)..."
	/usr/bin/python3 analyze.py $(FILE)

# ── Full demo flow (steps 1 → 2 → 4) ──────────────────────────────────────
run: start check demo

# ── Stop Qdrant ────────────────────────────────────────────────────────────
stop:
	@docker stop qdrant
	@echo "[✓] Qdrant stopped"

# ── Show saved reports ─────────────────────────────────────────────────────
reports:
	@echo "── Saved Reports ──────────────────"
	@ls -lt reports/*.md 2>/dev/null || echo "No reports yet"

.PHONY: start check index demo analyze run stop reports
