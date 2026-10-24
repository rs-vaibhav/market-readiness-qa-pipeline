import yaml

def parse_config(data: str):
    # Planted vulnerability: yaml.load with unsafe Loader
    return yaml.load(data, Loader=yaml.Loader)
