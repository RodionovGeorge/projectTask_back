#!/usr/bin/env bash
flask db init
#flask db stamp head
flask db migrate
flask db upgrade
python init_roles.py
uwsgi -s 0.0.0.0:5555 --wsgi-file /app/app.py --callable app
#uwsgi -s 0.0.0.0:5555  --lazy-apps --processes 4  --wsgi-file /app/app.py --callable app
