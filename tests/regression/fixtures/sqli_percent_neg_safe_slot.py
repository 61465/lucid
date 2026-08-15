def get(table):
    q = "SELECT * FROM %s WHERE 1=1" % table
    return q
