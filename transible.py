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
    - import_tasks: storage/images.yml
    - import_tasks: storage/volumes.yml
    - import_tasks: compute/keypairs.yml
    - import_tasks: compute/servers.yml
"""

NETWORK = {
    'networks.yml': 'create_networks',
    'subnets.yml': 'create_subnets',
    'security_groups.yml': 'create_security_groups',
    'routers.yml': 'create_routers'
}
STORAGE = {
    'images.yml': 'create_images',
    'volumes.yml': 'create_volumes',
}
COMPUTE = {
    'keypairs.yml': 'create_keypairs',
    'servers.yml': 'create_servers',
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
    },
    'volume': {
        'description': '',
        'name': '',
    },
    'image': {
        'disk_format': 'qcow2',
        'container_format': 'bare',
        'min_disk': 0,
        'min_ram': 0,
        'visibility': 'private',
        'is_protected': False,
    },
    'keypair': {},
    'server': {
        'security_groups': [{'name': 'default'}],
        'config_drive': '',
        'auto_ip': True,
        'boot_from_volume': False,
        'terminate_volume': False,
        'delete_fip': False,
        'reuse_ips': True,
    }
}

SKIP_UNNAMED_VOLUMES = True
IMAGES_AS_NAMES = True
USE_SERVER_IMAGES = True
CREATE_NEW_BOOT_VOLUMES = False
USE_EXISTING_BOOT_VOLUMES = False
NETWORK_AUTO = False
FIP_AUTO = True
STRICT_FIPS = not FIP_AUTO
STRICT_NETWORK_IPS = not NETWORK_AUTO


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
        if subnet['network_id'] in net_ids:
            s['network_name'] = net_ids[subnet['network_id']]
        else:
            print("subnet %s id=%s doesn't find its network id=%s" % (subnet['name'], subnet['id'], subnet['network_id']))
            continue
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
            n['provider_physical_network'] = network[
                'provider_physical_network']
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


def create_servers(data, file_):

    def get_boot_volume(volumes):
        # Let's assume it's only one bootable volume
        for v in volumes:
            vol = volumes_dict[v['id']]
            if not vol['is_bootable']:
                continue
            return vol

    def has_floating(addresses):
        return 'floating' in [
            j['OS-EXT-IPS:type'] for i in list(addresses.values()) for j in i]

    servers = []
    volumes_dict = {i['id']: i for i in data['volumes']}
    images_dict = {i['id']: i['name'] for i in data['images']}
    flavors_names = {i['id']: i['name'] for i in data['flavors']}
    for ser in data['servers']:
        s = {'state': 'present'}
        s['name'] = ser['name']
        if ser.get('location') and ser['location'].get('cloud'):
            s['cloud'] = ser['location']['cloud']
        if value(ser, 'server', 'security_groups'):
            s['security_groups'] = list(set(
                [i['name'] for i in ser['security_groups']]))
        s['flavor'] = flavors_names[ser['flavor']['id']]
        if value(ser, 'server', 'key_name'):
            s['key_name'] = ser['key_name']
        if value(ser, 'server', 'scheduler_hints'):
            s['scheduler_hints'] = ser['scheduler_hints']
        if value(ser, 'server', 'metadata'):
            s['meta'] = ser['metadata']
        if value(ser, 'server', 'config_drive'):
            s['config_drive'] = ser['config_drive'] == 'True'
        if value(ser, 'server', 'user_data'):
            s['userdata'] = ser['user_data']
        # Images and volumes
        if ser['image']['id']:
            if ser['image']['id'] in images_dict:
                s['image'] = ser['image']['id'] if not IMAGES_AS_NAMES else images_dict[
                    ser['image']['id']]
            else:
                print("Image with ID=%s of server %s is not in images list" % (ser['image']['id'], ser['name']))
                continue
        else:
            # Dancing with boot volumes
            if USE_EXISTING_BOOT_VOLUMES:
                s['boot_volume'] = get_boot_volume(
                    ser['attached_volumes'])['id']
                # s['volumes'] = [i['id'] for i in ser['attached_volumes']]
            elif USE_SERVER_IMAGES:
                meta = get_boot_volume(ser['attached_volumes'])[
                    'volume_image_metadata']
                s['image'] = (meta['image_name']
                              if IMAGES_AS_NAMES else meta['image_id'])
                if CREATE_NEW_BOOT_VOLUMES:
                    s['boot_from_volume'] = True
                    s['volume_size'] = get_boot_volume(
                        ser['attached_volumes'])['size']
        if ser.get('attached_volumes'):
            non_bootable_volumes = [i['id'] for i in ser['attached_volumes']
                                    if not volumes_dict[i['id']]['is_bootable']]
            if non_bootable_volumes:
                s['volumes'] = non_bootable_volumes
        if ser.get('addresses'):
            if NETWORK_AUTO:
                # In case of DHCP just connect to networks
                nics = [{"net-name": i} for i in list(ser['addresses'].keys())]
                s['nics'] = nics
            elif STRICT_NETWORK_IPS:
                s['nics'] = []
                for net in list(ser['addresses'].keys()):
                    for ip in ser['addresses'][net]:
                        if ip['OS-EXT-IPS:type'] == 'fixed':
                            s['nics'].append(
                                {'net-name': net, 'fixed_ip': ip['addr']})
            if FIP_AUTO:
                # If there are existing floating IPs only
                s['auto_ip'] = has_floating(ser['addresses'])
            elif STRICT_FIPS:
                fips = [j['addr'] for i in list(ser['addresses'].values())
                        for j in i if j['OS-EXT-IPS:type'] == 'floating']
                s['floating_ips'] = fips
        servers.append({'os_server': s})
    write_yaml(servers, file_)


def create_keypairs(data, file_):
    keypairs = []
    for key in data['keypairs']:
        k = {'state': 'present'}
        k['name'] = key['name']
        if key.get('location') and key['location'].get('cloud'):
            k['cloud'] = key['location']['cloud']
        if value(key, 'keypair', 'public_key'):
            k['public_key'] = key['public_key']
        keypairs.append({'os_keypair': k})
    write_yaml(keypairs, file_)


def create_images(data, file_, set_id=False):
    imgs = []
    for img in data['images']:
        im = {'state': 'present'}
        im['name'] = img['name']
        if set_id:
            im['id'] = img['id']
        if img.get('location') and img['location'].get('cloud'):
            im['cloud'] = img['location']['cloud']
        if value(img, 'image', 'checksum'):
            im['checksum'] = img['checksum']
        if value(img, 'image', 'container_format'):
            im['container_format'] = img['container_format']
        if value(img, 'image', 'disk_format'):
            im['disk_format'] = img['disk_format']
        if value(img, 'image', 'owner_id'):
            im['owner'] = img['owner_id']
        if value(img, 'image', 'min_disk'):
            im['min_disk'] = img['min_disk']
        if value(img, 'image', 'min_ram'):
            im['min_ram'] = img['min_ram']
        if value(img, 'image', 'visibility'):
            im['is_public'] = (img['visibility'] == 'public')
        # Supported in ansible > 2.8
        # if value(img, 'image', 'is_protected'):
        #     im['protected'] = img['is_protected']
        if value(img, 'image', 'file'):
            im['filename'] = img['file']
        if value(img, 'image', 'ramdisk_id'):
            im['ramdisk'] = img['ramdisk_id']
        if value(img, 'image', 'kernel_id'):
            im['kernel'] = img['kernel_id']
        if value(img, 'image', 'volume'):
            im['volume'] = img['volume']
        if value(img, 'image', 'properties'):
            im['properties'] = img['properties']
        imgs.append({'os_image': im})
    write_yaml(imgs, file_)


def create_volumes(data, file_):
    vols = []
    for vol in data['volumes']:
        v = {'state': 'present'}
        if not vol['name'] and SKIP_UNNAMED_VOLUMES:
            continue
        elif not vol['name']:
            v['display_name'] = vol['id']
        v['display_name'] = vol['name']
        if vol.get('location') and vol['location'].get('cloud'):
            v['cloud'] = vol['location']['cloud']
        if value(vol, 'volume', 'display_description'):
            v['display_description'] = vol['description']
        if value(vol, 'volume', 'size'):
            v['size'] = vol['size']
        if ('volume_image_metadata' in vol and 'image_name'
                in vol['volume_image_metadata']):
            v['image'] = vol['volume_image_metadata']['image_name']
        if value(vol, 'volume', 'metadata'):
            v['metadata'] = vol['metadata']
        if value(vol, 'volume', 'scheduler_hints'):
            v['scheduler_hints'] = vol['scheduler_hints']
        if value(vol, 'volume', 'snapshot_id'):
            v['snapshot_id'] = vol['snapshot_id']
        if value(vol, 'volume', 'source_volume_id'):
            v['volume'] = vol['source_volume_id']
        vols.append({'os_volume': v})
    write_yaml(vols, file_)


def main():
    conn = openstack.connect(cloud='openstack-nodepool')
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

    stor_data = {
        'images': [i for i in conn.image.images()],
        'volumes': [i for i in conn.volume.volumes()]
    }
    stor_funcs = {
        'create_images': create_images,
        'create_volumes': create_volumes,
    }
    comp_data = {
        'servers': [i for i in conn.compute.servers()],
        'keypairs': [i for i in conn.compute.keypairs()],
        'flavors': [i for i in conn.compute.flavors()],
        'images': stor_data['images'],
        'volumes': stor_data['volumes'],
    }
    comp_funcs = {
        'create_keypairs': create_keypairs,
        'create_servers': create_servers,
    }
    stor_path = os.path.join(PLAYS, "storage")
    if not os.path.exists(stor_path):
        os.makedirs(stor_path)
    for stor_file in STORAGE:
        path = os.path.join(stor_path, stor_file)
        func = stor_funcs[STORAGE[stor_file]]
        func(stor_data, path)
    comp_path = os.path.join(PLAYS, "compute")
    if not os.path.exists(comp_path):
        os.makedirs(comp_path)
    for comp_file in COMPUTE:
        path = os.path.join(comp_path, comp_file)
        func = comp_funcs[COMPUTE[comp_file]]
        func(comp_data, path)
    with open(os.path.join(PLAYS, "playbook.yml"), "w") as f:
        f.write(PLAYBOOK)


if __name__ == "__main__":
    main()
