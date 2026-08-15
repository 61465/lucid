import os
def read(p):
    if os.path.exists(p):
        try:
            f = open(p)
            return f.read()
        except OSError:
            return None
