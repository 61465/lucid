def parse_items(items):
    out = []
    for idx, item in enumerate(items):
        try:
            out.append(int(item))
        except ValueError:
            continue
    return out
