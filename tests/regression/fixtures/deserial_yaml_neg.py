import yaml
def load(s):
    return yaml.load(s, Loader=yaml.SafeLoader)
