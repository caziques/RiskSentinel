#!/bin/sh
set -e

echo "==> Initialising database…"
python - <<'PYEOF'
from app import app, db
from models import User, NewsFeed
with app.app_context():
    db.create_all()
    if not User.query.first():
        admin = User(username='admin', email='admin@local', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print('  Created default admin  →  admin / admin123')
    else:
        print('  Database already initialised.')
    if not NewsFeed.query.first():
        db.session.add(NewsFeed(
            name='Unit 42 — Palo Alto Networks',
            url='https://unit42.paloaltonetworks.com/feed/',
        ))
        db.session.commit()
        print('  Seeded default news feed.')
PYEOF

echo "==> Starting gunicorn on :8080"
exec gunicorn \
    --bind 0.0.0.0:8080 \
    --workers "${WORKERS:-2}" \
    --timeout "${TIMEOUT:-120}" \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --access-logfile - \
    --error-logfile - \
    app:app
