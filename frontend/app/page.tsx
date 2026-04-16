'use client';

import { useState } from 'react';
import { AnalyzeSection } from '@/components/AnalyzeSection';
import { ResultSection } from '@/components/ResultSection';

export default function Home() {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async (contract: string, name: string) => {
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch('http://localhost:8080/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contract, name }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Analysis failed');
      }

      const data = await response.json();
      setResult(data);
    } catch (err: any) {
      setResult({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 24px 80px' }}>
      <div style={{ textAlign: 'center', marginBottom: 48 }}>
        <h1 style={{ fontSize: 48, fontWeight: 700, marginBottom: 12, letterSpacing: '-0.02em' }}>
          RAXC Security Scanner
        </h1>
        <p style={{ fontSize: 18, color: 'var(--text-muted)', maxWidth: 600, margin: '0 auto' }}>
          RAG-powered vulnerability detection using real exploit patterns from DeFiHackLabs
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: result ? '1fr 1fr' : '1fr', gap: 24 }}>
        <AnalyzeSection onAnalyze={handleAnalyze} loading={loading} />
        {result && <ResultSection result={result} />}
      </div>
    </div>
  );
}
