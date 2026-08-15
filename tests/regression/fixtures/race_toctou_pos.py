import os
def read(p):
    if os.path.exists(p):
        f = open(p)
        return f.read()
