DEFAULTS = {
    'network': {
        'is_shared': False,
        'is_admin_state_up': True,
        'is_router_external': False,
        'is_port_security_enabled': True,
        'mtu': 1450,
    },
    'server': {

    }
}

PLAYBOOK = """
---
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    state: present
  module_defaults:
    group/aws:
      aws_access_key: '{{ aws_access_key | default(omit) }}'
      aws_secret_key: '{{ aws_secret_key | default(omit) }}'
      region: '{{ region | default(omit) }}'
  tasks:

    - include_vars: vars/main.yml
"""
NET_PLAYBOOK = """
    - import_tasks: networks/networks.yml
    - import_tasks: networks/subnets.yml
    - import_tasks: networks/security_groups.yml
    - import_tasks: networks/routers.yml
    - import_tasks: networks/nat_gateways.yml
    - import_tasks: networks/route_tables.yml
"""
STORAGE_PLAYBOOK = """
    - import_tasks: storage/images.yml
    - import_tasks: storage/volumes.yml
"""
COMPUTE_PLAYBOOK = """
    - import_tasks: compute/keypairs.yml
    - import_tasks: compute/servers.yml
"""
IDENTITY_PLAYBOOK = """
    - import_tasks: identity/users.yml
"""

PLAYBOOK_DELETE = """
---
# Playbook to nuke all generated resources
- hosts: localhost
  connection: local
  gather_facts: false
  module_defaults:
    group/aws:
      aws_access_key: '{{ aws_access_key | default(omit) }}'
      aws_secret_key: '{{ aws_secret_key | default(omit) }}'
      region: '{{ region | default(omit) }}'
  vars:
    state: absent
  tasks:

    - include_vars: vars/main.yml
"""
NET_PLAYBOOK_D = """
    - import_tasks: networks/route_tables.yml
    - import_tasks: networks/nat_gateways.yml
    - import_tasks: networks/routers.yml
    - import_tasks: networks/security_groups.yml
    - import_tasks: networks/subnets.yml
    - import_tasks: networks/networks.yml

"""
STORAGE_PLAYBOOK_D = """
    - import_tasks: storage/images.yml
    - import_tasks: storage/volumes.yml
"""
COMPUTE_PLAYBOOK_D = """
    - import_tasks: compute/servers.yml
    - import_tasks: compute/keypairs.yml
"""
IDENTITY_PLAYBOOK_D = """
    - import_tasks: identity/users.yml
"""

FILE_NETWORKS = 'networks.yml'
FILE_SUBNETS = 'subnets.yml'
FILE_SECURITY_GROUPS = 'security_groups.yml'
FILE_ROUTERS = 'routers.yml'
FILE_ROUTE_TBS = 'route_tables.yml'
FILE_NAT_GWS = 'nat_gateways.yml'
FILE_EIPS = "eips.yml"
FILE_LBS = "load_balancers.yml"
FILE_IMAGES = 'images.yml'
FILE_VOLUMES = 'volumes.yml'
FILE_KEYPAIRS = 'keypairs.yml'
FILE_SERVERS = 'servers.yml'
FILE_USERS = "users.yml"
FILE_DOMAINS = "domains.yml"
FILE_PROJECTS = "projects.yml"
FILE_ALL_DATA = "all_data.yml"
FILE_DHCPS = "dhcpopts.yml"
