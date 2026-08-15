import hashlib
def sign(d):
    return hashlib.sha256(d).hexdigest()
