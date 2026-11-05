import sqlite3
import subprocess
import shutil
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_db = os.path.join(BASE_DIR, "data", "honeytrack.db")
root_db = os.path.join(BASE_DIR, "honeytrack.db")

# 1. Sync data/honeytrack.db to root honeytrack.db
if os.path.exists(data_db):
    shutil.copy2(data_db, root_db)
    print(f"[+] Synced {data_db} -> {root_db}")

c = sqlite3.connect(data_db)
c.row_factory = sqlite3.Row
users = c.execute("SELECT * FROM users").fetchall()
attacks = c.execute("SELECT * FROM attack_events").fetchall()
c.close()

print(f"[+] SQLite has {len(users)} users and {len(attacks)} attacks.")
for u in users:
    print(f"    - User: ID={u['id']}, Name={u['name']}, Email={u['email']}")

# 2. Sync to TimescaleDB if container is running
print("\n[+] Syncing records into TimescaleDB container...")
for u in users:
    p_hash = u['password_hash'].replace("'", "''")
    name = u['name'].replace("'", "''")
    email = u['email'].replace("'", "''")
    q = f"INSERT INTO users (name, email, password_hash, created_at) VALUES ('{name}', '{email}', '{p_hash}', '{u['created_at']}') ON CONFLICT (email) DO NOTHING;"
    subprocess.run(["docker", "exec", "honeytrack-timescaledb", "psql", "-U", "postgres", "-d", "honeytrack", "-c", q], capture_output=True)

cols = ['timestamp', 'source_ip', 'service', 'username', 'password', 'command', 'user_agent', 'country', 'city', 'isp', 'latitude', 'longitude', 'attack_type', 'risk_score', 'is_tor', 'is_demo', 'origin_node']

for a in attacks:
    vals = []
    for col in cols:
        val = a[col]
        if val is None:
            vals.append("NULL")
        elif col in ('is_tor', 'is_demo'):
            vals.append("TRUE" if val else "FALSE")
        elif isinstance(val, (int, float)):
            vals.append(str(val))
        elif isinstance(val, bool):
            vals.append("TRUE" if val else "FALSE")
        else:
            escaped = str(val).replace("'", "''")
            vals.append(f"'{escaped}'")
    q = f"INSERT INTO attack_events ({', '.join(cols)}) VALUES ({', '.join(vals)});"
    subprocess.run(["docker", "exec", "honeytrack-timescaledb", "psql", "-U", "postgres", "-d", "honeytrack", "-c", q], capture_output=True)

res = subprocess.run(["docker", "exec", "honeytrack-timescaledb", "psql", "-U", "postgres", "-d", "honeytrack", "-c", "SELECT id, name, email FROM users; SELECT count(*) FROM attack_events;"], capture_output=True, text=True)
print("\n[+] TimescaleDB verification:")
print(res.stdout)
