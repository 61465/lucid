def get(uid):
    q = "SELECT * FROM t WHERE id = {}".format(uid)
    return q
