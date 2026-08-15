import re
def m(s):
    return re.compile("(.+)+").match(s)
