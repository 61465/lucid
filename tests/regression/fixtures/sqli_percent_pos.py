def get(uid):
    q = "SELECT * FROM t WHERE id = %s" % uid
    return q
