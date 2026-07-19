def a():
    try:
        1/0
    except Exception:
        print("something went wrong")
