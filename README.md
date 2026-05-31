# InvoiceAI

SaaS platform for freelancers to track and manage invoices.

## Architecture

- **frontend/** — Next.js 14 application (TypeScript, Tailwind CSS)
- **backend/** — FastAPI Python application (SQLite, REST API)

## Getting Started

### Backend

```bash
cd backend
pip install -r requirements.txt   # or the equivalent dependency manager
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Environment Variables

Copy `.env.example` to `.env` and configure the values:

- `DATABASE_URL` — Backend database connection string
- `SECRET_KEY` — Backend signing key
- `NEXT_PUBLIC_API_URL` — Frontend API base URL

## Features

- Invoice creation and management
- Client management
- Dashboard with statistics
- PDF generation
- Search and filtering
