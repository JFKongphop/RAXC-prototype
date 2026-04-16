'use client';

import { useState } from 'react';

interface AnalyzeSectionProps {
  onAnalyze: (contract: string, name: string) => Promise<void>;
  loading: boolean;
}

export function AnalyzeSection({ onAnalyze, loading }: AnalyzeSectionProps) {
  const [contract, setContract] = useState('');
  const [name, setName] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!contract.trim()) return;
    await onAnalyze(contract, name || 'contract');
  };

  const sampleContract = `pragma solidity ^0.8.0;

contract Reentrancy {
  mapping(address => uint) public balances;

  function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount;
  }
}`;

  const loadSample = () => {
    setContract(sampleContract);
    setName('Reentrancy');
  };

  return (
    <div className="card">
      <div className="card-header">📝 Contract Input</div>

      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>
            Contract Name (optional)
          </label>
          <input
            type="text"
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="MyContract"
            disabled={loading}
            style={{ fontFamily: 'var(--font-sans)' }}
          />
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>
            Solidity Contract Code
          </label>
          <textarea
            className="textarea"
            value={contract}
            onChange={(e) => setContract(e.target.value)}
            placeholder="// Paste your Solidity contract here..."
            disabled={loading}
          />
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading || !contract.trim()}
            style={{ flex: 1 }}
          >
            {loading ? (
              <>
                <div className="spinner" />
                Analyzing...
              </>
            ) : (
              '🔍 Analyze Contract'
            )}
          </button>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={loadSample}
            disabled={loading}
          >
            Load Sample
          </button>
        </div>
      </form>

      <div style={{ marginTop: 20, padding: 16, background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--text-dim)' }}>
        <strong style={{ color: 'var(--text-muted)' }}>How it works:</strong><br />
        1. Paste your Solidity contract<br />
        2. Embeddings match against 200+ real DeFi exploits<br />
        3. GPT-4o analyzes with exploit context<br />
        4. Get actionable security recommendations
      </div>
    </div>
  );
}
