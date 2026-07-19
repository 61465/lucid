import signal
def a():
    signal.signal(2, lambda *a: None)
