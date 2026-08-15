import hashlib
def sign(d):
    return hashlib.md5(d).hexdigest()
