def a():
    for i in range(3):
        try:
            1/0
        except Exception:
            continue
