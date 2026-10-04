import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.database import Base, engine, SessionLocal
from database.repositories import save_event, get_events, get_total_events


def test_database():

    # Create tables
    Base.metadata.create_all(bind=engine)

    # Create database session
    db = SessionLocal()

    try:
        # Sample attack event
        event_data = {
            "source_ip": "192.168.1.100",
            "service": "SSH",
            "username": "admin",
            "password": "123456",
            "command": "whoami",
            "user_agent": None,
            "country": "India",
            "city": "Bengaluru",
            "isp": "Demo ISP",
            "latitude": 12.9716,
            "longitude": 77.5946,
            "attack_type": "brute_force",
            "risk_score": 75,
            "is_tor": False
        }

        # Save event
        event = save_event(db, event_data)

        print("Event saved successfully!")
        print("Event ID:", event.id)

        # Retrieve events
        events = get_events(db)

        print("Total events returned:", len(events))

        # Count events
        total = get_total_events(db)

        print("Total events in database:", total)

    finally:
        db.close()


if __name__ == "__main__":
    test_database()