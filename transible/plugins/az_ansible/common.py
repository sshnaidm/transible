from functools import partial
from transible.plugins.az_ansible.const import DEFAULTS
from transible.plugins.az_ansible.config import VARS_PATH
from transible.utils import utils_write_yaml

write_yaml = partial(utils_write_yaml, vars_path=VARS_PATH)


def value(data, name, key):
    if key not in data:
        return False
    if data[key] is None:
        return False
    if not isinstance(data[key], bool) and not data[key]:
        return False
    if data[key] == DEFAULTS[name].get(key):
        return False
    return True
