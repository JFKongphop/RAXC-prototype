import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'RAXC | Smart Contract Security Scanner',
  description: 'RAG-powered vulnerability detection for Solidity smart contracts',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <nav className="nav-pill">
          <div className="nav-brand">🛡️ RAXC</div>
        </nav>
        <main style={{ paddingTop: 100 }}>
          {children}
        </main>
      </body>
    </html>
  );
}
