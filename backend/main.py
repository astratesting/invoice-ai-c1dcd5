"""
InvoiceAI Backend API — FastAPI application for invoice management.

Provides REST API endpoints for:
- User authentication (register, login, profile)
- Client management (CRUD)
- Invoice management (CRUD with line items, status transitions)
- Dashboard statistics
- Invoice PDF generation
- Search/filter invoices
"""

import os
import io
import csv
import json
import uuid
import hashlib
import secrets
import datetime
from typing import Optional
from enum import Enum
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Query, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field, EmailStr, field_validator
import uvicorn


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./invoiceai.db")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours


# ---------------------------------------------------------------------------
# Simple SQLite wrapper (no ORM dependency beyond stdlib)
# ---------------------------------------------------------------------------

import sqlite3
import threading

_local = threading.local()


def get_db() -> sqlite3.Connection:
    """Get a thread-local database connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        db_path = DATABASE_URL.replace("sqlite:///", "")
        if db_path == DATABASE_URL:
            db_path = "./invoiceai.db"
        _local.conn = sqlite3.connect(db_path, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            company_name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            phone TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS invoices (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
            invoice_number TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            issue_date TEXT NOT NULL DEFAULT (date('now')),
            due_date TEXT NOT NULL DEFAULT (date('now', '+30 days')),
            notes TEXT NOT NULL DEFAULT '',
            subtotal REAL NOT NULL DEFAULT 0.0,
            tax_rate REAL NOT NULL DEFAULT 0.0,
            tax_amount REAL NOT NULL DEFAULT 0.0,
            total REAL NOT NULL DEFAULT 0.0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS line_items (
            id TEXT PRIMARY KEY,
            invoice_id TEXT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
            description TEXT NOT NULL,
            quantity REAL NOT NULL DEFAULT 1,
            unit_price REAL NOT NULL DEFAULT 0,
            amount REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_clients_user ON clients(user_id);
        CREATE INDEX IF NOT EXISTS idx_invoices_user ON invoices(user_id);
        CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
        CREATE INDEX IF NOT EXISTS idx_invoices_client ON invoices(client_id);
        CREATE INDEX IF NOT EXISTS idx_line_items_invoice ON line_items(invoice_id);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_invoice_number_user
            ON invoices(user_id, invoice_number);
    """)
    conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="InvoiceAI API",
    description="Backend API for the InvoiceAI SaaS application",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def generate_id() -> str:
    return uuid.uuid4().hex[:24]


def hash_password(password: str) -> str:
    salt = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex() + ":" + salt


def verify_password(password: str, stored: str) -> bool:
    try:
        pw_hash, salt = stored.split(":")
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex() == pw_hash
    except (ValueError, AttributeError):
        return False


def create_token(user_id: str) -> str:
    """Create a simple bearer token (HMAC-signed)."""
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = f"{user_id}:{exp.isoformat()}:{SECRET_KEY}"
    sig = hashlib.sha256(payload.encode()).hexdigest()
    return f"{user_id}:{exp.isoformat()}:{sig}"


def decode_token(token: str) -> Optional[str]:
    """Validate token and return user_id or None."""
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return None
        user_id, exp_str, sig = parts
        exp = datetime.datetime.fromisoformat(exp_str)
        if exp < datetime.datetime.now(datetime.timezone.utc):
            return None
        expected = hashlib.sha256(f"{user_id}:{exp_str}:{SECRET_KEY}".encode()).hexdigest()
        if sig != expected:
            return None
        return user_id
    except (ValueError, AttributeError):
        return None


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """Dependency: extract and validate the current user from Bearer token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid authorization scheme")
    user_id = decode_token(token.strip())
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(row)


def next_invoice_number(conn: sqlite3.Connection, user_id: str) -> str:
    """Generate the next sequential invoice number for a user."""
    row = conn.execute(
        "SELECT invoice_number FROM invoices WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    if row:
        last_num = int(row["invoice_number"].replace("INV-", ""))
        return f"INV-{last_num + 1:05d}"
    return "INV-00001"


# ---------------------------------------------------------------------------
# Enums / Status
# ---------------------------------------------------------------------------

class InvoiceStatus(str, Enum):
    draft = "draft"
    sent = "sent"
    paid = "paid"
    overdue = "overdue"
    cancelled = "cancelled"


VALID_TRANSITIONS = {
    InvoiceStatus.draft: [InvoiceStatus.sent, InvoiceStatus.cancelled],
    InvoiceStatus.sent: [InvoiceStatus.paid, InvoiceStatus.overdue, InvoiceStatus.cancelled],
    InvoiceStatus.paid: [],
    InvoiceStatus.overdue: [InvoiceStatus.paid, InvoiceStatus.cancelled],
    InvoiceStatus.cancelled: [],
}


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

# -- Auth --

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=6, max_length=128)
    name: str = Field(..., min_length=1, max_length=255)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email address")
        return v.strip().lower()


class LoginRequest(BaseModel):
    email: str
    password: str


class AuthResponse(BaseModel):
    token: str
    user: dict


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    company_name: str
    created_at: str
    updated_at: str


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    company_name: Optional[str] = None
    email: Optional[str] = None


# -- Client --

class ClientCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    email: str = Field(default="", max_length=255)
    phone: str = Field(default="", max_length=50)
    address: str = Field(default="", max_length=500)


class ClientUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None


class ClientResponse(BaseModel):
    id: str
    user_id: str
    name: str
    email: str
    phone: str
    address: str
    created_at: str
    updated_at: str


# -- Line Items --

class LineItemCreate(BaseModel):
    description: str = Field(..., min_length=1, max_length=500)
    quantity: float = Field(default=1, gt=0)
    unit_price: float = Field(default=0, ge=0)


class LineItemResponse(BaseModel):
    id: str
    invoice_id: str
    description: str
    quantity: float
    unit_price: float
    amount: float
    created_at: str


# -- Invoice --

class InvoiceCreate(BaseModel):
    client_id: str
    issue_date: Optional[str] = None
    due_date: Optional[str] = None
    notes: str = Field(default="", max_length=2000)
    tax_rate: float = Field(default=0, ge=0, le=100)
    line_items: list[LineItemCreate] = Field(..., min_length=1)


class InvoiceUpdate(BaseModel):
    client_id: Optional[str] = None
    issue_date: Optional[str] = None
    due_date: Optional[str] = None
    notes: Optional[str] = None
    tax_rate: Optional[float] = None
    line_items: Optional[list[LineItemCreate]] = None


class InvoiceStatusUpdate(BaseModel):
    status: InvoiceStatus


class InvoiceResponse(BaseModel):
    id: str
    user_id: str
    client_id: str
    client_name: str
    invoice_number: str
    status: str
    issue_date: str
    due_date: str
    notes: str
    subtotal: float
    tax_rate: float
    tax_amount: float
    total: float
    line_items: list[LineItemResponse]
    created_at: str
    updated_at: str


# -- Dashboard --

class DashboardStats(BaseModel):
    total_invoices: int
    total_paid: int
    total_pending: int
    total_overdue: int
    total_cancelled: int
    total_draft: int
    total_revenue: float
    pending_revenue: float
    overdue_revenue: float


# -- Search --

class InvoiceFilterParams(BaseModel):
    status: Optional[str] = None
    client_id: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    search: Optional[str] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

# -- Health --

@app.get("/api/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}


# -- Auth --

@app.post("/api/auth/register", status_code=201)
def register(body: RegisterRequest):
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (body.email,)).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user_id = generate_id()
    pw_hash = hash_password(body.password)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO users (id, email, name, password_hash, company_name, created_at, updated_at) VALUES (?, ?, ?, ?, '', ?, ?)",
        (user_id, body.email, body.name, pw_hash, now, now),
    )
    conn.commit()
    token = create_token(user_id)
    return AuthResponse(
        token=token,
        user={
            "id": user_id,
            "email": body.email,
            "name": body.name,
            "company_name": "",
            "created_at": now,
            "updated_at": now,
        },
    )


@app.post("/api/auth/login")
def login(body: LoginRequest):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (body.email.strip().lower(),)).fetchone()
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    user = dict(row)
    token = create_token(user["id"])
    return AuthResponse(
        token=token,
        user={
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "company_name": user["company_name"],
            "created_at": user["created_at"],
            "updated_at": user["updated_at"],
        },
    )


@app.get("/api/auth/me")
def get_profile(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "name": current_user["name"],
        "company_name": current_user["company_name"],
        "created_at": current_user["created_at"],
        "updated_at": current_user["updated_at"],
    }


@app.put("/api/auth/me")
def update_profile(body: UpdateProfileRequest, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.company_name is not None:
        updates["company_name"] = body.company_name
    if body.email is not None:
        existing = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", (body.email, current_user["id"])).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Email already in use")
        updates["email"] = body.email
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    updates["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [current_user["id"]]
    conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (current_user["id"],)).fetchone()
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "company_name": row["company_name"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


# -- Clients --

@app.get("/api/clients")
def list_clients(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM clients WHERE user_id = ? ORDER BY name ASC",
        (current_user["id"],),
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/clients", status_code=201)
def create_client(body: ClientCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    client_id = generate_id()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO clients (id, user_id, name, email, phone, address, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (client_id, current_user["id"], body.name.strip(), body.email.strip(), body.phone.strip(), body.address.strip(), now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    return dict(row)


@app.get("/api/clients/{client_id}")
def get_client(client_id: str, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM clients WHERE id = ? AND user_id = ?",
        (client_id, current_user["id"]),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Client not found")
    return dict(row)


@app.put("/api/clients/{client_id}")
def update_client(client_id: str, body: ClientUpdate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    existing = conn.execute(
        "SELECT * FROM clients WHERE id = ? AND user_id = ?",
        (client_id, current_user["id"]),
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Client not found")
    updates = {}
    if body.name is not None:
        updates["name"] = body.name.strip()
    if body.email is not None:
        updates["email"] = body.email.strip()
    if body.phone is not None:
        updates["phone"] = body.phone.strip()
    if body.address is not None:
        updates["address"] = body.address.strip()
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    updates["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [client_id]
    conn.execute(f"UPDATE clients SET {set_clause} WHERE id = ?", values)
    conn.commit()
    row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    return dict(row)


@app.delete("/api/clients/{client_id}")
def delete_client(client_id: str, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    existing = conn.execute(
        "SELECT * FROM clients WHERE id = ? AND user_id = ?",
        (client_id, current_user["id"]),
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Client not found")
    invoice_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM invoices WHERE client_id = ?", (client_id,)
    ).fetchone()["cnt"]
    if invoice_count > 0:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete client with {invoice_count} existing invoice(s). Remove or reassign invoices first.",
        )
    conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    conn.commit()
    return {"detail": "Client deleted"}


# -- Invoices --

@app.get("/api/invoices")
def list_invoices(
    status: Optional[str] = Query(None),
    client_id: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    conn = get_db()
    conditions = ["i.user_id = ?"]
    params: list = [current_user["id"]]

    if status:
        conditions.append("i.status = ?")
        params.append(status)
    if client_id:
        conditions.append("i.client_id = ?")
        params.append(client_id)
    if date_from:
        conditions.append("i.issue_date >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("i.issue_date <= ?")
        params.append(date_to)
    if search:
        conditions.append("(c.name LIKE ? OR i.invoice_number LIKE ? OR i.notes LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])

    where = " AND ".join(conditions)

    count_row = conn.execute(
        f"SELECT COUNT(*) as cnt FROM invoices i JOIN clients c ON c.id = i.client_id WHERE {where}",
        params,
    ).fetchone()
    total = count_row["cnt"]

    offset = (page - 1) * page_size
    rows = conn.execute(
        f"""
        SELECT i.*, c.name as client_name
        FROM invoices i
        JOIN clients c ON c.id = i.client_id
        WHERE {where}
        ORDER BY i.created_at DESC
        LIMIT ? OFFSET ?
        """,
        params + [page_size, offset],
    ).fetchall()

    results = []
    for row in rows:
        inv = dict(row)
        items = conn.execute(
            "SELECT * FROM line_items WHERE invoice_id = ? ORDER BY created_at ASC",
            (inv["id"],),
        ).fetchall()
        inv["line_items"] = [dict(it) for it in items]
        results.append(inv)

    total_pages = max(1, (total + page_size - 1) // page_size)
    return {
        "data": results,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
        },
    }


@app.post("/api/invoices", status_code=201)
def create_invoice(body: InvoiceCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    client = conn.execute(
        "SELECT * FROM clients WHERE id = ? AND user_id = ?",
        (body.client_id, current_user["id"]),
    ).fetchone()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    invoice_id = generate_id()
    inv_number = next_invoice_number(conn, current_user["id"])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    issue_date = body.issue_date or datetime.date.today().isoformat()
    due_date = body.due_date or (datetime.date.today() + datetime.timedelta(days=30)).isoformat()

    subtotal = sum(item.quantity * item.unit_price for item in body.line_items)
    tax_amount = round(subtotal * body.tax_rate / 100, 2)
    total = round(subtotal + tax_amount, 2)

    conn.execute(
        """
        INSERT INTO invoices (id, user_id, client_id, invoice_number, status, issue_date, due_date, notes, subtotal, tax_rate, tax_amount, total, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (invoice_id, current_user["id"], body.client_id, inv_number, issue_date, due_date, body.notes.strip(),
         subtotal, body.tax_rate, tax_amount, total, now, now),
    )

    for item in body.line_items:
        li_id = generate_id()
        amount = round(item.quantity * item.unit_price, 2)
        conn.execute(
            "INSERT INTO line_items (id, invoice_id, description, quantity, unit_price, amount, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (li_id, invoice_id, item.description.strip(), item.quantity, item.unit_price, amount, now),
        )

    conn.commit()

    row = conn.execute("SELECT i.*, c.name as client_name FROM invoices i JOIN clients c ON c.id = i.client_id WHERE i.id = ?", (invoice_id,)).fetchone()
    inv = dict(row)
    items = conn.execute("SELECT * FROM line_items WHERE invoice_id = ? ORDER BY created_at ASC", (invoice_id,)).fetchall()
    inv["line_items"] = [dict(it) for it in items]
    return inv


@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: str, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute(
        "SELECT i.*, c.name as client_name FROM invoices i JOIN clients c ON c.id = i.client_id WHERE i.id = ? AND i.user_id = ?",
        (invoice_id, current_user["id"]),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Invoice not found")
    inv = dict(row)
    items = conn.execute(
        "SELECT * FROM line_items WHERE invoice_id = ? ORDER BY created_at ASC",
        (invoice_id,),
    ).fetchall()
    inv["line_items"] = [dict(it) for it in items]
    return inv


@app.put("/api/invoices/{invoice_id}")
def update_invoice(invoice_id: str, body: InvoiceUpdate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    existing = conn.execute(
        "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, current_user["id"]),
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Invoice not found")
    if existing["status"] != "draft":
        raise HTTPException(status_code=400, detail="Only draft invoices can be edited")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    updates = {"updated_at": now}

    if body.client_id is not None:
        client = conn.execute(
            "SELECT * FROM clients WHERE id = ? AND user_id = ?",
            (body.client_id, current_user["id"]),
        ).fetchone()
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        updates["client_id"] = body.client_id
    if body.issue_date is not None:
        updates["issue_date"] = body.issue_date
    if body.due_date is not None:
        updates["due_date"] = body.due_date
    if body.notes is not None:
        updates["notes"] = body.notes.strip()
    if body.tax_rate is not None:
        updates["tax_rate"] = body.tax_rate
    if body.line_items is not None:
        subtotal = sum(item.quantity * item.unit_price for item in body.line_items)
        tax_amount = round(subtotal * updates.get("tax_rate", existing["tax_rate"]) / 100, 2)
        updates["subtotal"] = round(subtotal, 2)
        updates["tax_amount"] = tax_amount
        updates["total"] = round(subtotal + tax_amount, 2)
        conn.execute("DELETE FROM line_items WHERE invoice_id = ?", (invoice_id,))
        for item in body.line_items:
            li_id = generate_id()
            amount = round(item.quantity * item.unit_price, 2)
            conn.execute(
                "INSERT INTO line_items (id, invoice_id, description, quantity, unit_price, amount, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (li_id, invoice_id, item.description.strip(), item.quantity, item.unit_price, amount, now),
            )

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [invoice_id]
    conn.execute(f"UPDATE invoices SET {set_clause} WHERE id = ?", values)
    conn.commit()

    row = conn.execute("SELECT i.*, c.name as client_name FROM invoices i JOIN clients c ON c.id = i.client_id WHERE i.id = ?", (invoice_id,)).fetchone()
    inv = dict(row)
    items = conn.execute("SELECT * FROM line_items WHERE invoice_id = ? ORDER BY created_at ASC", (invoice_id,)).fetchall()
    inv["line_items"] = [dict(it) for it in items]
    return inv


@app.patch("/api/invoices/{invoice_id}/status")
def update_invoice_status(invoice_id: str, body: InvoiceStatusUpdate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    existing = conn.execute(
        "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, current_user["id"]),
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Invoice not found")

    current_status = InvoiceStatus(existing["status"])
    new_status = body.status
    allowed = VALID_TRANSITIONS.get(current_status, [])
    if new_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot transition from '{current_status.value}' to '{new_status.value}'. Allowed: {[s.value for s in allowed]}",
        )

    if new_status == InvoiceStatus.overdue:
        due = datetime.date.fromisoformat(existing["due_date"])
        if due >= datetime.date.today():
            raise HTTPException(status_code=400, detail="Invoice is not past due date")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn.execute(
        "UPDATE invoices SET status = ?, updated_at = ? WHERE id = ?",
        (new_status.value, now, invoice_id),
    )
    conn.commit()

    row = conn.execute("SELECT i.*, c.name as client_name FROM invoices i JOIN clients c ON c.id = i.client_id WHERE i.id = ?", (invoice_id,)).fetchone()
    inv = dict(row)
    items = conn.execute("SELECT * FROM line_items WHERE invoice_id = ? ORDER BY created_at ASC", (invoice_id,)).fetchall()
    inv["line_items"] = [dict(it) for it in items]
    return inv


@app.delete("/api/invoices/{invoice_id}")
def delete_invoice(invoice_id: str, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    existing = conn.execute(
        "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, current_user["id"]),
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Invoice not found")
    if existing["status"] not in ("draft", "cancelled"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete invoice with status '{existing['status']}'. Only draft or cancelled invoices can be deleted.",
        )
    conn.execute("DELETE FROM invoices WHERE id = ?", (invoice_id,))
    conn.commit()
    return {"detail": "Invoice deleted"}


# -- Dashboard --

@app.get("/api/dashboard/stats")
def dashboard_stats(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    user_id = current_user["id"]

    total = conn.execute("SELECT COUNT(*) as cnt FROM invoices WHERE user_id = ?", (user_id,)).fetchone()["cnt"]
    paid = conn.execute("SELECT COUNT(*) as cnt FROM invoices WHERE user_id = ? AND status = 'paid'", (user_id,)).fetchone()["cnt"]
    pending = conn.execute("SELECT COUNT(*) as cnt FROM invoices WHERE user_id = ? AND status = 'sent'", (user_id,)).fetchone()["cnt"]
    overdue = conn.execute("SELECT COUNT(*) as cnt FROM invoices WHERE user_id = ? AND status = 'overdue'", (user_id,)).fetchone()["cnt"]
    draft = conn.execute("SELECT COUNT(*) as cnt FROM invoices WHERE user_id = ? AND status = 'draft'", (user_id,)).fetchone()["cnt"]
    cancelled = conn.execute("SELECT COUNT(*) as cnt FROM invoices WHERE user_id = ? AND status = 'cancelled'", (user_id,)).fetchone()["cnt"]

    revenue = conn.execute("SELECT COALESCE(SUM(total), 0) as sum FROM invoices WHERE user_id = ? AND status = 'paid'", (user_id,)).fetchone()["sum"]
    pending_rev = conn.execute("SELECT COALESCE(SUM(total), 0) as sum FROM invoices WHERE user_id = ? AND status = 'sent'", (user_id,)).fetchone()["sum"]
    overdue_rev = conn.execute("SELECT COALESCE(SUM(total), 0) as sum FROM invoices WHERE user_id = ? AND status = 'overdue'", (user_id,)).fetchone()["sum"]

    return DashboardStats(
        total_invoices=total,
        total_paid=paid,
        total_pending=pending,
        total_overdue=overdue,
        total_cancelled=cancelled,
        total_draft=draft,
        total_revenue=round(revenue, 2),
        pending_revenue=round(pending_rev, 2),
        overdue_revenue=round(overdue_rev, 2),
    )


@app.get("/api/dashboard/recent-invoices")
def recent_invoices(limit: int = Query(5, ge=1, le=50), current_user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        """
        SELECT i.*, c.name as client_name
        FROM invoices i
        JOIN clients c ON c.id = i.client_id
        WHERE i.user_id = ?
        ORDER BY i.created_at DESC
        LIMIT ?
        """,
        (current_user["id"], limit),
    ).fetchall()
    results = []
    for row in rows:
        inv = dict(row)
        items = conn.execute(
            "SELECT * FROM line_items WHERE invoice_id = ? ORDER BY created_at ASC",
            (inv["id"],),
        ).fetchall()
        inv["line_items"] = [dict(it) for it in items]
        results.append(inv)
    return results


@app.get("/api/dashboard/monthly-revenue")
def monthly_revenue(year: Optional[int] = None, current_user: dict = Depends(get_current_user)):
    if year is None:
        year = datetime.date.today().year
    conn = get_db()
    rows = conn.execute(
        """
        SELECT
            strftime('%m', issue_date) as month,
            COUNT(*) as invoice_count,
            COALESCE(SUM(total), 0) as revenue
        FROM invoices
        WHERE user_id = ? AND status = 'paid' AND strftime('%Y', issue_date) = ?
        GROUP BY month
        ORDER BY month ASC
        """,
        (current_user["id"], str(year)),
    ).fetchall()
    result = []
    for r in rows:
        result.append({
            "month": int(r["month"]),
            "invoice_count": r["invoice_count"],
            "revenue": round(r["revenue"], 2),
        })
    return result


# -- PDF Generation --

@app.get("/api/invoices/{invoice_id}/pdf")
def download_invoice_pdf(invoice_id: str, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute(
        "SELECT i.*, c.name as client_name, c.email as client_email, c.address as client_address, "
        "u.name as user_name, u.company_name as user_company, u.email as user_email "
        "FROM invoices i "
        "JOIN clients c ON c.id = i.client_id "
        "JOIN users u ON u.id = i.user_id "
        "WHERE i.id = ? AND i.user_id = ?",
        (invoice_id, current_user["id"]),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Invoice not found")

    items = conn.execute(
        "SELECT * FROM line_items WHERE invoice_id = ? ORDER BY created_at ASC",
        (invoice_id,),
    ).fetchall()

    inv = dict(row)
    company = inv["user_company"] or inv["user_name"]
    pdf_text = generate_invoice_pdf_text(inv, items, company)
    filename = f"invoice_{inv['invoice_number']}.txt"
    return StreamingResponse(
        io.BytesIO(pdf_text.encode("utf-8")),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def generate_invoice_pdf_text(inv: dict, items: list, company: str) -> str:
    """Generate a plain-text invoice representation (stand-in for PDF)."""
    lines = []
    lines.append("=" * 64)
    lines.append(f"  INVOICEAI")
    lines.append(f"  {company}")
    lines.append("=" * 64)
    lines.append("")
    lines.append(f"  Invoice #:     {inv['invoice_number']}")
    lines.append(f"  Status:        {inv['status'].upper()}")
    lines.append(f"  Issue Date:    {inv['issue_date']}")
    lines.append(f"  Due Date:      {inv['due_date']}")
    lines.append("")
    lines.append("-" * 64)
    lines.append("  BILL TO:")
    lines.append(f"  {inv['client_name']}")
    if inv.get("client_address"):
        for addr_line in inv["client_address"].split("\n"):
            lines.append(f"  {addr_line.strip()}")
    lines.append("-" * 64)
    lines.append("")
    lines.append(f"  {'Description':<30} {'Qty':>6} {'Price':>10} {'Amount':>10}")
    lines.append("  " + "-" * 58)
    for item in items:
        desc = item["description"][:28] if len(item["description"]) > 28 else item["description"]
        lines.append(f"  {desc:<30} {item['quantity']:>6.2f} {item['unit_price']:>10.2f} {item['amount']:>10.2f}")
    lines.append("  " + "-" * 58)
    lines.append(f"  {'Subtotal':>48} {inv['subtotal']:>10.2f}")
    if inv["tax_rate"] > 0:
        lines.append(f"  {'Tax (' + str(inv['tax_rate']) + '%)':>48} {inv['tax_amount']:>10.2f}")
    lines.append(f"  {'TOTAL':>48} {inv['total']:>10.2f}")
    lines.append("")
    if inv.get("notes"):
        lines.append("  Notes:")
        lines.append(f"  {inv['notes']}")
    lines.append("")
    lines.append("=" * 64)
    lines.append("  Thank you for your business!")
    lines.append("=" * 64)
    return "\n".join(lines)


# -- CSV Export --

@app.get("/api/invoices/export/csv")
def export_invoices_csv(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        """
        SELECT i.invoice_number, i.status, i.issue_date, i.due_date, i.subtotal, i.tax_amount, i.total,
               c.name as client_name
        FROM invoices i
        JOIN clients c ON c.id = i.client_id
        WHERE i.user_id = ?
        ORDER BY i.created_at DESC
        """,
        (current_user["id"],),
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Invoice Number", "Status", "Issue Date", "Due Date", "Subtotal", "Tax", "Total", "Client"])
    for r in rows:
        writer.writerow([r["invoice_number"], r["status"], r["issue_date"], r["due_date"],
                         r["subtotal"], r["tax_amount"], r["total"], r["client_name"]])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=invoices_export.csv"},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
