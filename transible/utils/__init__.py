import yaml


class ExtraDumper(yaml.Dumper):
    """Custom dumper for YAML
    """

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)

    def represent_str(self, data):
        if "{{" in data or "}}" in data:
            return self.represent_scalar('tag:yaml.org,2002:str', data, style='"')
        return self.represent_scalar('tag:yaml.org,2002:str', data)


ExtraDumper.add_representer(str, ExtraDumper.represent_str)


def str2bool(x):
    if isinstance(x, bool):
        return x
    if x in ['True', 'true', 1, 'T', 't', '1']:
        return True
    if x in ['False', 'false', 0, 'F', 'f', '0']:
        return False
    raise Exception("Please pass False or True instead of %s" % x)


def yaml_dump(content):
    return yaml.dump(content,
                     Dumper=ExtraDumper,
                     default_flow_style=False,
                     sort_keys=False,
                     width=120)


def add_vars(content, path, header=None, footer=None):
    with open(path, "a") as f:
        if header:
            f.write(header)
        f.write(yaml_dump(content))
        if footer:
            f.write(footer)


def read_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def utils_write_yaml(content, path, vars_path=None):
    for item in content:
        if 'vars' in item:
            item_vars = item.pop('vars')
            var_name = list(item_vars.keys())[0]
            add_vars(item_vars, vars_path, header="# %s section\n" % var_name)
    with open(path, "w") as f:
        f.write("---\n")
        f.write(yaml_dump(content))


def optimize(data, use_vars=True, var_name=None):
    if not data:
        return []
    all_keys = []
    for d in data:
        values = d.values()
        values = [v for v in values if isinstance(v, dict)]
        # Extract all possible keys from module
        all_keys += [j for i in list(values) for j in list(i) if isinstance(i, dict)]
    # Get a list of unique keys
    all_keys = list(set(all_keys))
    # Name of the module
    main_key = list(data[0].keys())[0]
    # Fullfil by value|default(omit)
    templ = {main_key: {k: "{{ item.%s | default(omit) }}" % k for k in all_keys}}
    templ.update({'loop': [list(i.values())[0] for i in data]})
    for k in all_keys:
        k_values = [i.get(k) for i in templ['loop']]
        if any((isinstance(y, dict) for y in k_values)):
            continue
        if any((isinstance(y, list) for y in k_values)):
            continue
        allv = list(set(k_values))
        if len(allv) == 1:
            templ[main_key][k] = allv[0]
            for d in templ['loop']:
                del d[k]
    if use_vars:
        var_list = templ.pop('loop')
        templ['loop'] = "{{ %s }}" % var_name
        templ['vars'] = {var_name: var_list}
    return templ
