def flaky_call(fn):
    for _ in range(5):
        try:
            return fn()
        except Exception:
            continue
