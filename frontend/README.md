# RAXC Frontend

Next.js frontend for the RAXC smart contract security scanner.

## Setup

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

## Requirements

- RAXC API running at `http://localhost:8080`
- Node.js 18+

## Features

- 📝 Contract input with syntax highlighting
- 🔍 Real-time analysis via RAXC API
- 📊 Visual results dashboard
- 📄 Full markdown report viewer
- 🎨 Dark theme matching Zringotts style

## Usage

1. Start the RAXC API:
   ```bash
   docker run -d -p 8080:8080 --env-file .env raxc-api
   ```

2. Start the frontend:
   ```bash
   cd frontend
   npm run dev
   ```

3. Open browser and analyze contracts!
