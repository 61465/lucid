def get(uid):
    q = "SELECT * FROM t WHERE id = " + str(uid)
    return q
