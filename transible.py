#!/usr/bin/python3

import os
import yaml

import openstack

PLAYS = os.path.join(os.path.curdir, "transible")
if not os.path.exists(PLAYS):
    os.makedirs(PLAYS)

PLAYBOOK = """
---
- hosts: localhost
  connection: local
  gather_facts: no
  tasks:

    - import_tasks: networks/networks.yml
    - import_tasks: networks/subnets.yml
    - import_tasks: networks/security_groups.yml
    - import_tasks: networks/routers.yml
    # - import_tasks: compute/keypairs.yml
    # - import_tasks: compute/servers.yml
"""

NETWORK = {
    'networks.yml': 'create_networks',
    'subnets.yml': 'create_subnets',
    'security_groups.yml': 'create_security_groups',
    'routers.yml': 'create_routers'
}
DEFAULTS = {
    'network': {
        'is_shared': False,
        'is_admin_state_up': True,
        'is_router_external': False,
        'is_port_security_enabled': True,
        'mtu': 1450,
    },
    'subnet': {
        'ip_version': 4
    },
    'security_group_rule': {
        'description': '',
        'direction': 'ingress',
        'ethertype': 'IPv4',
    },
    'security_group': {
        'description': '',
    },
    'router': {
        'is_admin_state_up': True,
    }
}


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


def write_yaml(content, path):
    with open(path, "w") as f:
        f.write("---\n")
        f.write(yaml.safe_dump(content))


def create_subnets(data, file_):
    subnets = []
    net_ids = {i['id']: i['name'] for i in data['networks']}
    for subnet in data['subnets']:
        s = {'state': 'present'}
        if subnet.get('location') and subnet['location'].get('cloud'):
            s['cloud'] = subnet['location']['cloud']
        s['name'] = subnet['name']
        s['network_name'] = net_ids[subnet['network_id']]
        s['cidr'] = subnet['cidr']
        if value(subnet, 'subnet', 'ip_version'):
            s['ip_version'] = subnet['ip_version']
        if value(subnet, 'subnet', 'enable_dhcp'):
            s['enable_dhcp'] = subnet['is_dhcp_enabled']
        if value(subnet, 'subnet', 'gateway_ip'):
            s['gateway_ip'] = subnet['gateway_ip']
        if value(subnet, 'subnet', 'dns_nameservers'):
            s['dns_nameservers'] = subnet['dns_nameservers']
        if value(subnet, 'subnet', 'ipv6_address_mode'):
            s['ipv6_address_mode'] = subnet['ipv6_address_mode']
        if value(subnet, 'subnet', 'ipv6_ra_mode'):
            s['ipv6_ra_mode'] = subnet['ipv6_ra_mode']
        if value(subnet, 'subnet', 'host_routes'):
            s['host_routes'] = subnet['host_routes']
        subnets.append({'os_subnet': s})
    write_yaml(subnets, file_)


def create_networks(data, file_):
    networks = []
    for network in data['networks']:
        n = {'state': 'present'}
        if network.get('location') and network['location'].get('cloud'):
            n['cloud'] = network['location']['cloud']
        n['name'] = network['name']
        if value(network, 'network', 'is_admin_state_up'):
            n['admin_state_up'] = network['is_admin_state_up']
        if value(network, 'network', 'is_router_external'):
            n['external'] = network['is_router_external']
        if value(network, 'network', 'is_port_security_enabled'):
            n['port_security_enabled'] = network['is_port_security_enabled']
        if value(network, 'network', 'is_shared'):
            n['shared'] = network['is_shared']
        if value(network, 'network', 'provider_network_type'):
            n['provider_network_type'] = network['provider_network_type']
        if value(network, 'network', 'provider_physical_network'):
            n['provider_physical_network'] = network['provider_physical_network']
        if value(network, 'network', 'provider_segmentation_id'):
            n['provider_segmentation_id'] = network['provider_segmentation_id']
        # if value(network, 'network', 'mtu'):
        #    n['mtu'] = network['mtu']
        if value(network, 'network', 'dns_domain'):
            n['dns_domain'] = network['dns_domain']
        networks.append({'os_network': n})
    write_yaml(networks, file_)


def create_security_groups(data, file_):
    secgrs = []
    secgrs_ids = {i['id']: i['name'] for i in data['secgroups']}
    for secgr in data['secgroups']:
        s = {'state': 'present'}
        if secgr.get('location') and secgr['location'].get('cloud'):
            s['cloud'] = secgr['location']['cloud']
        s['name'] = secgr['name']
        secgrs.append({'os_security_group': s})
        if value(secgr, 'security_group', 'description'):
            s['description'] = secgr['description']
        if secgr.get('security_group_rules'):
            for rule in secgr['security_group_rules']:
                r = {'security_group': secgr['name']}
                if s.get('cloud'):
                    r['cloud'] = s['cloud']
                if value(rule, 'security_group_rule', 'description'):
                    r['description'] = rule['description']
                if value(rule, 'security_group_rule', 'ethertype'):
                    r['ethertype'] = rule['ethertype']
                if value(rule, 'security_group_rule', 'direction'):
                    r['direction'] = rule['direction']
                if value(rule, 'security_group_rule', 'port_range_max'):
                    r['port_range_max'] = rule['port_range_max']
                if value(rule, 'security_group_rule', 'port_range_min'):
                    r['port_range_min'] = rule['port_range_min']
                if value(rule, 'security_group_rule', 'protocol'):
                    r['protocol'] = rule['protocol']
                if value(rule, 'security_group_rule', 'remote_group_id'):
                    r['remote_group'] = secgrs_ids[rule['remote_group_id']]
                if value(rule, 'security_group_rule', 'remote_ip_prefix'):
                    r['remote_ip_prefix'] = rule['remote_ip_prefix']
                secgrs.append({'os_security_group_rule': r})
    write_yaml(secgrs, file_)


def create_routers(data, file_, strict_ip=False):
    routers = []
    # secgrs_ids = {i['id']: i['name'] for i in data}
    subnet_ids = {i['id']: i for i in data['subnets']}
    net_ids = {i['id']: i for i in data['networks']}
    for rout in data['routers']:
        r = {'state': 'present'}
        if rout.get('location') and rout['location'].get('cloud'):
            r['cloud'] = rout['location']['cloud']
        r['name'] = rout['name']
        if value(rout, 'router', 'is_admin_state_up'):
            r['admin_state_up'] = rout['is_admin_state_up']
        r['interfaces'] = []
        ports = [i for i in data['ports'] if i['device_id'] == rout['id']]
        for p in ports:
            for fip in p['fixed_ips']:
                subnet = subnet_ids.get(fip['subnet_id'])
                if not subnet:
                    raise Exception("No subnet with ID=%s" % fip['subnet_id'])
                if subnet['gateway_ip'] == fip['ip_address']:
                    r['interfaces'].append(subnet['name'])
                else:
                    net = net_ids.get(p['network_id'])
                    if not net:
                        raise Exception("No network with ID=%s" %
                                        p['network_id'])
                    net_name = net['name']
                    subnet_name = subnet['name']
                    portip = fip['ip_address']
                    r['interfaces'].append({
                        'net': net_name,
                        'subnet': subnet_name,
                        'portip': portip,
                    })
        if not r['interfaces']:
            del r['interfaces']
        if rout['external_gateway_info']:
            ext_net = net_ids.get(rout['external_gateway_info']['network_id'])
            if not ext_net:
                raise Exception("No net with ID=%s" % rout[
                    'external_gateway_info']['network_id'])
            ext_net_name = ext_net['name']
            r['network'] = ext_net_name
            if len(rout['external_gateway_info']['external_fixed_ips']) == 1:
                ext = rout['external_gateway_info']['external_fixed_ips'][0]
                if strict_ip:
                    ext_sub_id = ext['subnet_id']
                    ext_subnet = subnet_ids.get(ext_sub_id)
                    if not ext_subnet:
                        # raise Exception("No subnet with ID=%s" % ext_sub_id)
                        ext_sub_name = ext_sub_id
                    else:
                        ext_sub_name = ext_subnet['name']
                    ext_fip = ext['ip_address']
                    r['external_fixed_ips'] = [{
                        'subnet': ext_sub_name,
                        'ip': ext_fip
                    }]
            if len(rout['external_gateway_info']['external_fixed_ips']) > 1:
                ext_ips = rout['external_gateway_info']['external_fixed_ips']
                for ext in ext_ips:
                    ext_sub_id = ext['subnet_id']
                    ext_subnet = subnet_ids.get(ext_sub_id)
                    if not ext_subnet:
                        # raise Exception("No subnet with ID=%s" % ext_sub_id)
                        ext_sub_name = ext_sub_id
                    else:
                        ext_sub_name = ext_subnet['name']
                    ext_fip = ext['ip_address']
                    r['external_fixed_ips'] = [{
                        'subnet': ext_sub_name,
                        'ip': ext_fip
                    }]
        routers.append({'os_router': r})
    write_yaml(routers, file_)


def main():
    conn = openstack.connect(cloud='rdo-cloud')
    # openstack.enable_logging(debug=True)
    nets = [i for i in conn.network.networks()]
    subnets = [i for i in conn.network.subnets()]
    secgroups = [i for i in conn.network.security_groups()]
    routers = [i for i in conn.network.routers()]
    ports = [i for i in conn.network.ports()]
    data = {
        'networks': nets,
        'subnets': subnets,
        'secgroups': secgroups,
        'routers': routers,
        'ports': ports
    }
    funcs = {
        'create_networks': create_networks,
        'create_subnets': create_subnets,
        'create_security_groups': create_security_groups,
        'create_routers': create_routers,

    }
    net_path = os.path.join(PLAYS, "networks")
    if not os.path.exists(net_path):
        os.makedirs(net_path)
    for net_file in NETWORK:
        path = os.path.join(net_path, net_file)
        func = funcs[NETWORK[net_file]]
        func(data, path)
    with open(os.path.join(PLAYS, "playbook.yml"), "w") as f:
        f.write(PLAYBOOK)


if __name__ == "__main__":
    main()
