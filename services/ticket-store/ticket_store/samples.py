"""Synthetic tickets for screen work and demos. Every row is data_origin=sample."""
import json
from pathlib import Path

from . import db

SAMPLES = Path(__file__).with_name("samples") / "tickets.json"


def sample_tickets():
    return json.loads(SAMPLES.read_text(encoding="utf-8"))


def load_samples(conn):
    """Insert sample tickets that are not stored yet. Returns how many were added."""
    added = 0
    with conn:
        for ticket in sample_tickets():
            if conn.execute("SELECT 1 FROM tickets WHERE ticket_id = ?", (ticket["ticket_id"],)).fetchone():
                continue
            db.insert_ticket(conn, ticket)
            added += 1
    return added
