import time
def with_backoff(fn):
    for _ in range(5):
        try:
            return fn()
        except Exception:
            time.sleep(1)
            continue
