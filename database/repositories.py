from sqlalchemy.orm import Session

from .models import AttackEvent


def save_event(db: Session, event_data: dict):
    """
    Save a new attack event to the database.
    """
    valid_cols = {c.name for c in AttackEvent.__table__.columns}
    filtered = {k: v for k, v in event_data.items() if k in valid_cols}
    event = AttackEvent(**filtered)

    db.add(event)
    db.commit()
    db.refresh(event)

    return event


def get_events(db: Session, limit: int = 100):
    """
    Get the latest attack events.
    """

    return (
        db.query(AttackEvent)
        .order_by(AttackEvent.timestamp.desc())
        .limit(limit)
        .all()
    )


def get_event_by_id(db: Session, event_id: int):
    """
    Get one attack event using its ID.
    """

    return (
        db.query(AttackEvent)
        .filter(AttackEvent.id == event_id)
        .first()
    )


def get_total_events(db: Session):
    """
    Return the total number of attack events.
    """

    return db.query(AttackEvent).count()


def get_unique_ips(db: Session):
    """
    Return the number of unique attacker IP addresses.
    """

    return db.query(AttackEvent.source_ip).distinct().count()