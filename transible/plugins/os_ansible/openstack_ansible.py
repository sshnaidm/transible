#!/usr/bin/python3


import os
import openstack

from transible.plugins.os_ansible import config as conf
from transible.plugins.os_ansible import const
from transible.plugins.os_ansible.common import value, optimize, write_yaml, read_yaml


class OpenstackAnsible:
    """Main class to generate Ansible playbooks from OpenStack

    Args:
        cloud_name (string): cloud name from clouds.yaml config file
        debug (bool, optional): debug option. Defaults to False.
        from_file (str, optional): Optional file with all data. Defaults to ''.
    """
    def __init__(self, cloud_name, debug=False, from_file=''):
        self.path = {}
        self.initialize_directories()
        self.data = {}
        if from_file:
            self.data = read_yaml(os.path.join(conf.DATA_DIR_TRANSIENT, from_file))
        else:
            oi = OpenstackInfo(cloud_name=cloud_name, debug=debug)
            oi.run()
            self.data = oi.data
        self.debug = debug
        self.data.update({'cloud': cloud_name})
        self.os_calc = OpenstackCalculation(self.data, debug=self.debug)

    def initialize_directories(self):
        if not os.path.exists(conf.PLAYS):
            os.makedirs(conf.PLAYS)
        if not os.path.exists(os.path.dirname(conf.VARS_PATH)):
            os.makedirs(os.path.dirname(conf.VARS_PATH))
        with open(conf.VARS_PATH, "w") as e:
            e.write("---\n")
        dirs_matrix = {
            'networks': conf.DUMP_NETWORKS,
            'storage': conf.DUMP_STORAGE,
            'compute': conf.DUMP_SERVERS,
            'identity': conf.DUMP_IDENTITY,
        }

        for dir_type, dump in dirs_matrix.items():
            if dump:
                self.path[dir_type] = os.path.join(conf.PLAYS, dir_type)
                if not os.path.exists(self.path[dir_type]):
                    os.makedirs(self.path[dir_type])
        if conf.DATA_DIR_TRANSIENT:
            if not os.path.exists(conf.DATA_DIR_TRANSIENT):
                os.makedirs(conf.DATA_DIR_TRANSIENT)

    def run(self):
        for data_type, dump in {
            'networks': conf.DUMP_NETWORKS,
            'storage': conf.DUMP_STORAGE,
            'compute': conf.DUMP_SERVERS,
            'identity': conf.DUMP_IDENTITY,
        }.items():
            if dump:
                self.retrieve_cloud_data(data_type)
        self.write_playbook()

    def retrieve_cloud_data(self, data_type):
        cloud_funcs = {
            const.FILE_NETWORKS: ('networks', self.os_calc.create_networks),
            const.FILE_SUBNETS: ('networks', self.os_calc.create_subnets),
            const.FILE_SECURITY_GROUPS: ('networks', self.os_calc.create_security_groups),
            const.FILE_ROUTERS: ('networks', self.os_calc.create_routers),
            const.FILE_IMAGES: ('storage', self.os_calc.create_images),
            const.FILE_VOLUMES: ('storage', self.os_calc.create_volumes),
            const.FILE_FLAVORS: ('compute', self.os_calc.create_flavors),
            const.FILE_KEYPAIRS: ('compute', self.os_calc.create_keypairs),
            const.FILE_SERVERS: ('compute', self.os_calc.create_servers),
            const.FILE_PROJECTS: ('identity', self.os_calc.create_projects),
            const.FILE_DOMAINS: ('identity', self.os_calc.create_domains),
            const.FILE_USERS: ('identity', self.os_calc.create_users),
        }
        for file_name, (path, func) in cloud_funcs.items():
            if path == data_type:
                path = os.path.join(self.path[path], file_name)
                dumped_data = func()  # pylint: disable=not-callable
                write_yaml(dumped_data, path)

    def write_playbook(self):
        playbook = const.PLAYBOOK
        play_matrix = {
            const.NET_PLAYBOOK: conf.DUMP_NETWORKS,
            const.STORAGE_PLAYBOOK: conf.DUMP_STORAGE,
            const.COMPUTE_PLAYBOOK: conf.DUMP_SERVERS,
            const.IDENTITY_PLAYBOOK: conf.DUMP_IDENTITY,
        }
        for play, dump in play_matrix.items():
            if dump:
                playbook += play
        with open(os.path.join(conf.PLAYS, "playbook.yml"), "w") as f:
            f.write(playbook)


class OpenstackInfo:
    """Retrieve information about Openstack cloud

    Args:
        cloud_name (str): cloud name from clouds.yaml config file
        debug (bool, optional): debug option. Defaults to False.
    """
    def __init__(self, cloud_name, debug=False):
        self.debug = debug
        self.data = {}
        self.cloud = cloud_name

    def run(self):
        self.get_info()

    def get_info(self):
        conn = openstack.connect(cloud=self.cloud)
        # pylint: disable=maybe-no-member
        if self.debug:
            openstack.enable_logging(debug=True)
        info_matrix = {
            'networks': (conf.DUMP_NETWORKS, conn.network.networks, const.FILE_NETWORKS),
            'subnets': (conf.DUMP_NETWORKS, conn.network.subnets, const.FILE_SUBNETS),
            'secgroups': (conf.DUMP_NETWORKS, conn.network.security_groups, const.FILE_SECURITY_GROUPS),
            'routers': (conf.DUMP_NETWORKS, conn.network.routers, const.FILE_ROUTERS),
            'ports': (conf.DUMP_NETWORKS, conn.network.ports, const.FILE_PORTS),
            'images': (conf.DUMP_STORAGE, conn.image.images, const.FILE_IMAGES),
            'volumes': (conf.DUMP_STORAGE, conn.volume.volumes, const.FILE_VOLUMES),
            # 'volumes': (conf.DUMP_STORAGE, conn.block_storage.volumes, const.FILE_VOLUMES),
            # 'floating_ips': (conf.DUMP_NETWORKS, conn.network.floating_ips, const.FILE_FIPS),
            'keypairs': (conf.DUMP_SERVERS, conn.compute.keypairs, const.FILE_KEYPAIRS),
            'servers': (conf.DUMP_SERVERS, conn.compute.servers, const.FILE_SERVERS),
            'flavors': (conf.DUMP_SERVERS, conn.compute.flavors, const.FILE_FLAVORS),
            'users': (conf.DUMP_IDENTITY, conn.identity.users, const.FILE_FLAVORS),
            'projects': (conf.DUMP_IDENTITY, conn.identity.projects, const.FILE_PROJECTS),
            'domains': (conf.DUMP_IDENTITY, conn.identity.domains, const.FILE_DOMAINS),
        }
        for data_type, (dump, func, file_name) in info_matrix.items():
            if dump:
                self.data[data_type] = list((i.to_dict() for i in func()))
                # Remove Munch objects from the dict
                for i in self.data[data_type]:
                    i.pop('location')
                self.dump2file(file_name, data_type)

        if conf.DATA_DIR_TRANSIENT:
            write_yaml(self.data, os.path.join(conf.DATA_DIR_TRANSIENT,
                                               const.FILE_ALL_DATA))

    def dump2file(self, path, data_type):
        if conf.DATA_DIR_TRANSIENT:
            write_yaml(
                self.data[data_type],
                os.path.join(conf.DATA_DIR_TRANSIENT, path))


class OpenstackCalculation:
    """Class to generate all Ansible playbooks.

    Args:
            data (dict): Openstack info data to be used to generate the playbooks.
            debug (bool, optional): debug option. Defaults to False.
    """
    def __init__(self, data, debug=False):
        self.debug = debug
        self.data = data

    def create_projects(self, force_optimize=conf.VARS_OPT_PROJECTS,
                        vars_file=True):
        projects = []
        pre_optimized = []
        for pro in self.data['projects']:
            p = {'state': 'present'}
            p['cloud'] = self.data['cloud']
            p['name'] = pro['name']
            if value(pro, 'project', 'is_enabled'):
                p['enabled'] = pro['is_enabled']
            if value(pro, 'project', 'description'):
                p['description'] = pro['description']
            if value(pro, 'project', 'domain_id'):
                p['domain_id'] = pro['domain_id']
            if force_optimize:
                pre_optimized.append({'openstack.cloud.project': p})
            else:
                projects.append({'openstack.cloud.project': p})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="projects")
            if optimized:
                projects.append(optimized)
        return projects

    def create_domains(self, force_optimize=conf.VARS_OPT_DOMAINS,
                       vars_file=True):
        domains = []
        pre_optimized = []
        for dom in self.data['domains']:
            d = {'state': 'present'}
            d['cloud'] = self.data['cloud']
            d['name'] = dom['name']
            if value(dom, 'domain', 'is_enabled'):
                d['enabled'] = dom['is_enabled']
            if value(dom, 'domain', 'description'):
                d['description'] = dom['description']
            if force_optimize:
                pre_optimized.append({'openstack.cloud.identity_domain': d})
            else:
                domains.append({'openstack.cloud.identity_domain': d})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="domains")
            if optimized:
                domains.append(optimized)
        return domains

    def create_users(self, force_optimize=conf.VARS_OPT_USERS,
                     vars_file=True):
        users = []
        pre_optimized = []
        domains_by_id = {d['id']: d['name'] for d in self.data['domains']}
        projects_by_id = {d['id']: d['name'] for d in self.data['projects']}
        for user in self.data['users']:
            u = {'state': 'present'}
            u['cloud'] = self.data['cloud']
            u['name'] = user['name']
            if value(user, 'user', 'is_enabled'):
                u['enabled'] = user['is_enabled']
            if value(user, 'user', 'description'):
                u['description'] = user['description']
            if value(user, 'user', 'domain_id'):
                u['domain'] = domains_by_id[user['domain_id']]
            if value(user, 'user', 'default_project_id'):
                u['default_project'] = projects_by_id[user['default_project_id']]
            if value(user, 'user', 'email'):
                u['email'] = user['email']
            if value(user, 'user', 'password'):  # shouldn't be there
                u['password'] = user['password']
            if force_optimize:
                pre_optimized.append({'openstack.cloud.identity_user': u})
            else:
                users.append({'openstack.cloud.identity_user': u})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="users")
            if optimized:
                users.append(optimized)
        return users

    def create_flavors(self, force_optimize=conf.VARS_OPT_FLAVORS,
                       vars_file=True):
        flavors = []
        pre_optimized = []
        for flavor in self.data['flavors']:
            fl = {'state': 'present'}
            fl['cloud'] = self.data['cloud']
            fl['name'] = flavor['name']
            if value(flavor, 'flavor', 'disk'):
                fl['disk'] = flavor['disk']
            if value(flavor, 'flavor', 'ram'):
                fl['ram'] = flavor['ram']
            if value(flavor, 'flavor', 'vcpus'):
                fl['vcpus'] = flavor['vcpus']
            if value(flavor, 'flavor', 'swap'):
                fl['swap'] = flavor['swap']
            if value(flavor, 'flavor', 'rxtx_factor'):
                fl['rxtx_factor'] = flavor['rxtx_factor']
            if value(flavor, 'flavor', 'is_public'):
                fl['is_public'] = flavor['is_public']
            if value(flavor, 'flavor', 'ephemeral'):
                fl['ephemeral'] = flavor['ephemeral']
            if value(flavor, 'flavor', 'extra_specs'):
                fl['extra_specs'] = flavor['extra_specs']
            if force_optimize:
                pre_optimized.append({'openstack.cloud.compute_flavor': fl})
            else:
                flavors.append({'openstack.cloud.compute_flavor': fl})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="flavors")
            if optimized:
                flavors.append(optimized)
        return flavors

    def create_subnets(self, force_optimize=conf.VARS_OPT_SUBNETS,
                       vars_file=True):
        subnets = []
        pre_optimized = []
        net_ids = {i['id']: i['name'] for i in self.data['networks']}
        for subnet in self.data['subnets']:
            s = {'state': 'present'}
            s['cloud'] = self.data['cloud']
            s['name'] = subnet['name']
            if subnet['network_id'] in net_ids:
                s['network_name'] = net_ids[subnet['network_id']]
            else:
                print("subnet %s id=%s doesn't find its network id=%s" %
                      (subnet['name'], subnet['id'], subnet['network_id']))
                continue
            s['cidr'] = subnet['cidr']
            if value(subnet, 'subnet', 'ip_version'):
                s['ip_version'] = subnet['ip_version']
            if value(subnet, 'subnet', 'is_dhcp_enabled'):
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
            if force_optimize:
                pre_optimized.append({'openstack.cloud.subnet': s})
            else:
                subnets.append({'openstack.cloud.subnet': s})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="subnets")
            if optimized:
                subnets.append(optimized)
        return subnets

    def create_networks(self, force_optimize=conf.VARS_OPT_NETWORKS,
                        vars_file=True):
        networks = []
        pre_optimized = []
        for network in self.data['networks']:
            n = {'state': 'present'}
            n['cloud'] = self.data['cloud']
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
                n['provider_segmentation_id'] = network[
                    'provider_segmentation_id']
            # if value(network, 'network', 'mtu'):
            #    n['mtu'] = network['mtu']
            if value(network, 'network', 'dns_domain'):
                n['dns_domain'] = network['dns_domain']
            if force_optimize:
                pre_optimized.append({'openstack.cloud.network': n})
            else:
                networks.append({'openstack.cloud.network': n})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="networks")
            if optimized:
                networks.append(optimized)
        return networks

    def create_security_groups(self,
                               force_optimize=conf.VARS_OPT_SECGROUPS,
                               vars_file=True):
        secgrs = []
        secgrs_ids = {i['id']: i['name'] for i in self.data['secgroups']}
        for secgr in self.data['secgroups']:
            s = {'state': 'present'}
            s['cloud'] = self.data['cloud']
            s['name'] = secgr['name']
            project = ''
            if self.data['projects']:
                project_ids = {i['id']: i for i in self.data['projects']}
                if secgr.get('project_id'):
                    project = project_ids[secgr['project_id']]['name']
                    s['project'] = project
            secgrs.append({'openstack.cloud.security_group': s})
            if value(secgr, 'security_group', 'description'):
                s['description'] = secgr['description']
            if secgr.get('security_group_rules'):
                pre_optimized = []
                for rule in secgr['security_group_rules']:
                    r = {'security_group': secgr['name']}
                    if project:
                        r['project'] = project
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
                    if force_optimize:
                        pre_optimized.append({'openstack.cloud.security_group_rule': r})
                    else:
                        secgrs.append({'openstack.cloud.security_group_rule': r})
                if force_optimize:
                    var_name = (
                        secgr['name'].replace('-', '_')
                        + ("_" + project if project else '')
                        + "_rules")
                    optimized = optimize(
                        pre_optimized,
                        use_vars=vars_file,
                        var_name=var_name)
                    if optimized:
                        secgrs.append(optimized)
        return secgrs

    def create_routers(self, strict_ip=False,
                       force_optimize=conf.VARS_OPT_ROUTERS, vars_file=True):
        routers = []
        pre_optimized = []
        subnet_ids = {i['id']: i for i in self.data['subnets']}
        net_ids = {i['id']: i for i in self.data['networks']}
        for rout in self.data['routers']:
            r = {'state': 'present'}
            r['cloud'] = self.data['cloud']
            r['name'] = rout['name']
            if value(rout, 'router', 'is_admin_state_up'):
                r['admin_state_up'] = rout['is_admin_state_up']
            r['interfaces'] = []
            ports = [i for i in self.data['ports']
                     if i['device_id'] == rout['id']]
            for p in ports:
                for fip in p['fixed_ips']:
                    subnet = subnet_ids.get(fip['subnet_id'])
                    if not subnet:
                        raise Exception("No subnet with ID=%s" %
                                        fip['subnet_id'])
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
                ext_net = net_ids.get(
                    rout['external_gateway_info']['network_id'])
                if not ext_net:
                    raise Exception("No net with ID=%s" % rout[
                                    'external_gateway_info']['network_id'])
                ext_net_name = ext_net['name']
                r['network'] = ext_net_name
                if len(rout['external_gateway_info']['external_fixed_ips']
                       ) == 1:
                    ext = rout['external_gateway_info']['external_fixed_ips'][0]
                    if strict_ip:
                        ext_sub_id = ext['subnet_id']
                        ext_subnet = subnet_ids.get(ext_sub_id)
                        if not ext_subnet:
                            # raise Exception("No subnet with ID" )
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
            if force_optimize:
                pre_optimized.append({'openstack.cloud.router': r})
            else:
                routers.append({'openstack.cloud.router': r})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="routers")
            if optimized:
                routers.append(optimized)
        return routers

    def create_servers(self, force_optimize=conf.VARS_OPT_SERVERS,
                       vars_file=True):

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
        pre_optimized = []
        if conf.DUMP_STORAGE:
            volumes_dict = {i['id']: i for i in self.data['volumes']}
            images_dict = {i['id']: i['name'] for i in self.data['images']}
        else:
            volumes_dict = {}
            images_dict = {}
        flavors_names = {i['id']: i['name'] for i in self.data['flavors']}
        for ser in self.data['servers']:
            s = {'state': 'present'}
            s['name'] = ser['name']
            s['cloud'] = self.data['cloud']
            if value(ser, 'server', 'security_groups'):
                s['security_groups'] = list(
                    {i['name'] for i in ser['security_groups']})
            if 'original_name' in ser['flavor']:
                s['flavor'] = ser['flavor']['original_name']
            elif ser['flavor_id']:
                s['flavor'] = flavors_names[ser['flavor_id']]
            else:
                raise Exception("Flavor for server %s not found! %s" % (
                    ser['name'], str(ser['flavor'])))
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
                    s['image'] = (
                        ser['image']['id']
                        if not conf.IMAGES_AS_NAMES
                        else images_dict[ser['image']['id']])
                else:
                    print("Image with ID=%s of server %s is not in images list" %
                          (ser['image']['id'], ser['name']))
                    continue
            else:
                # Dancing with boot volumes
                if conf.USE_EXISTING_BOOT_VOLUMES:
                    s['boot_volume'] = get_boot_volume(
                        ser['attached_volumes'])['id']
                    # s['volumes'] = [i['id'] for i in ser['attached_volumes']]
                elif conf.USE_SERVER_IMAGES:
                    meta = get_boot_volume(ser['attached_volumes'])[
                        'volume_image_metadata']
                    s['image'] = (meta['image_name']
                                  if conf.IMAGES_AS_NAMES else meta['image_id'])
                    if conf.CREATE_NEW_BOOT_VOLUMES:
                        s['boot_from_volume'] = True
                        s['volume_size'] = get_boot_volume(
                            ser['attached_volumes'])['size']
            if ser.get('attached_volumes'):
                non_bootable_volumes = [i['id'] for i in ser['attached_volumes']
                                        if not volumes_dict[i['id']]['is_bootable']]
                if non_bootable_volumes:
                    s['volumes'] = non_bootable_volumes
            if ser.get('addresses'):
                if conf.NETWORK_AUTO:
                    # In case of DHCP just connect to networks
                    nics = [{"net-name": i}
                            for i in list(ser['addresses'].keys())]
                    s['nics'] = nics
                elif conf.STRICT_NETWORK_IPS:
                    s['nics'] = []
                    for net in list(ser['addresses'].keys()):
                        for ip in ser['addresses'][net]:
                            if ip['OS-EXT-IPS:type'] == 'fixed':
                                s['nics'].append(
                                    {'net-name': net, 'fixed_ip': ip['addr']})
                if conf.FIP_AUTO:
                    # If there are existing floating IPs only
                    s['auto_ip'] = has_floating(ser['addresses'])
                elif conf.STRICT_FIPS:
                    fips = [j['addr'] for i in list(ser['addresses'].values())
                            for j in i if j['OS-EXT-IPS:type'] == 'floating']
                    s['floating_ips'] = fips
            if force_optimize:
                pre_optimized.append({'openstack.cloud.server': s})
            else:
                servers.append({'openstack.cloud.server': s})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="servers")
            if optimized:
                servers.append(optimized)
        return servers

    def create_keypairs(self, force_optimize=conf.VARS_OPT_KEYPAIRS,
                        vars_file=True):
        keypairs = []
        pre_optimized = []
        for key in self.data['keypairs']:
            k = {'state': 'present'}
            k['name'] = key['name']
            k['cloud'] = self.data['cloud']
            if value(key, 'keypair', 'public_key'):
                k['public_key'] = key['public_key']
            if force_optimize:
                pre_optimized.append({'openstack.cloud.keypair': k})
            else:
                keypairs.append({'openstack.cloud.keypair': k})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="keypairs")
            if optimized:
                keypairs.append(optimized)
        return keypairs

    def create_images(self, set_id=False,
                      force_optimize=conf.VARS_OPT_IMAGES, vars_file=True):
        imgs = []
        pre_optimized = []
        for img in self.data['images']:
            im = {'state': 'present'}
            im['name'] = img['name']
            if set_id:
                im['id'] = img['id']
            im['cloud'] = self.data['cloud']
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
            if force_optimize:
                pre_optimized.append({'openstack.cloud.image': im})
            else:
                imgs.append({'openstack.cloud.image': im})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="images")
            if optimized:
                imgs.append(optimized)
        return imgs

    def create_volumes(self, force_optimize=conf.VARS_OPT_VOLUMES,
                       vars_file=True):
        vols = []
        pre_optimized = []
        for vol in self.data['volumes']:
            v = {'state': 'present'}
            if not vol['name'] and conf.SKIP_UNNAMED_VOLUMES:
                continue
            if not vol['name']:
                v['display_name'] = vol['id']
            v['display_name'] = vol['name']
            v['cloud'] = self.data['cloud']
            if value(vol, 'volume', 'display_description'):
                v['display_description'] = vol['description']
            if value(vol, 'volume', 'size'):
                v['size'] = vol['size']
            if ('volume_image_metadata' in vol
                and vol['volume_image_metadata']
                    and 'image_name' in vol['volume_image_metadata']):
                v['image'] = vol['volume_image_metadata']['image_name']
            if value(vol, 'volume', 'metadata'):
                v['metadata'] = vol['metadata']
            if value(vol, 'volume', 'scheduler_hints'):
                v['scheduler_hints'] = vol['scheduler_hints']
            if value(vol, 'volume', 'snapshot_id'):
                v['snapshot_id'] = vol['snapshot_id']
            if value(vol, 'volume', 'source_volume_id'):
                v['volume'] = vol['source_volume_id']
            if force_optimize:
                pre_optimized.append({'openstack.cloud.volume': v})
            else:
                vols.append({'openstack.cloud.volume': v})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="volumes")
            if optimized:
                vols.append(optimized)
        return vols


def main():
    playbook = OpenstackAnsible("test-cloud")
    playbook.run()


if __name__ == "__main__":
    main()
