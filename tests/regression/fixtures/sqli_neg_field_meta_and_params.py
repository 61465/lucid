def query(source):
    where = []
    params = []
    if source != 'all':
        where.append('source = ?')
        params.append(source)
    where_sql = ' AND '.join(where)
    sql = f"SELECT * FROM listings WHERE {where_sql} LIMIT ?"
    return sql
