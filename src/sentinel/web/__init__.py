"""Server-rendered web UI: session-cookie auth, CSRF, Jinja2 templates.

Kept deliberately separate from `sentinel.api`, which is the JSON/Bearer-token
surface. See `session.py` for the cookie/CSRF scheme and `routes.py` for the pages.
"""
