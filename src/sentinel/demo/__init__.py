"""Demo harness: scenario definitions and a client shared by `sentinel-demo` (the
narrated CLI, see `cli.py`) and the e2e test suite (`tests/e2e/`), so both drive the
real running stack through the exact same calls rather than two parallel
implementations that could silently drift apart.
"""
