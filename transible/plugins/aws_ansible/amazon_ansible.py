import os
import logging

import boto3

from transible.plugins.aws_ansible import config as conf
from transible.plugins.aws_ansible import const
from transible.plugins.aws_ansible.common import write_yaml
from transible.utils import read_yaml, optimize


class AmazonAnsible:
    """Main class to generate Ansible playbooks from Amazon

    Args:
        debug (bool, optional): debug option. Defaults to False.
        from_file (str, optional): Optional file with all data. Defaults to ''.
    """
    def __init__(self, debug=False, from_file=''):
        self.path = {}
        self.initialize_directories()
        self.data = {}
        if from_file:
            self.data = read_yaml(os.path.join(conf.DATA_DIR_TRANSIENT, from_file))
        else:
            ai = AmazonInfo(debug=debug)
            ai.run()
            self.data = ai.data
        self.debug = debug
        self.aws_calc = AmazonAnsibleCalculation(self.data, debug=self.debug)

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
            const.FILE_NETWORKS: ('networks', self.aws_calc.create_vpcs),
            const.FILE_SUBNETS: ('networks', self.aws_calc.create_subnets),
            const.FILE_SECURITY_GROUPS: ('networks', self.aws_calc.create_security_groups),
            const.FILE_ROUTERS: ('networks', self.aws_calc.create_routers),
            const.FILE_ROUTE_TBS: ('networks', self.aws_calc.create_route_tables),
            const.FILE_NAT_GWS: ('networks', self.aws_calc.create_nat_gateways),

            # const.FILE_IMAGES: ('storage', self.aws_calc.create_images),
            # const.FILE_VOLUMES: ('storage', self.aws_calc.create_volumes),
            const.FILE_KEYPAIRS: ('compute', self.aws_calc.create_keypairs),
            const.FILE_SERVERS: ('compute', self.aws_calc.create_servers),
            # const.FILE_PROJECTS: ('identity', self.aws_calc.create_projects),
            # const.FILE_DOMAINS: ('identity', self.aws_calc.create_domains),
            # const.FILE_USERS: ('identity', self.aws_calc.create_users),
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


class AmazonAnsibleCalculation:
    """Class to generate all Ansible playbooks.

    Args:
            data (dict): Amazon info data to be used to generate the playbooks.
            debug (bool, optional): debug option. Defaults to False.
    """
    def __init__(self, data, debug=False):
        self.debug = debug
        self.data = data

    def create_dhcpopts(self, force_optimize=conf.VARS_OPT_DHCPOPTS,
                        vars_file=True):
        dopts = []
        pre_optimized = []
        for dhcp in self.data['dhcpopts']:
            d = {'state': 'present'}
            d['dhcp_options_id'] = dhcp['DhcpOptionsId']
            if dhcp.get('Tags'):
                d['tags'] = {t['Key']: t['Value'] for t in dhcp['Tags']
                             if not t['Key'].startswith('aws:')}
            key_pair = {'amazon.aws.ec2_vpc_dhcp_option': d}
            if force_optimize:
                pre_optimized.append(key_pair)
            else:
                dopts.append(key_pair)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="dhcpopts")
            if optimized:
                dopts.append(optimized)
        return dopts

    def create_vpcs(self, force_optimize=conf.VARS_OPT_NETWORKS,
                    vars_file=True):
        vpcs = []
        pre_optimized = []
        for vpc in self.data['networks']:
            n = {'state': 'present'}
            n['cidr_block'] = vpc['CidrBlock']
            n['dhcp_opts_id'] = vpc['DhcpOptionsId']
            n['multi_ok'] = False
            if vpc['IsDefault']:
                n['name'] = vpc['VpcId']
            if 'Tags' in vpc:
                n['tags'] = {t['Key']: t['Value'] for t in vpc['Tags']
                             if not t['Key'].startswith('aws:')}
                n['name'] = n['tags']['Name']
            if 'InstanceTenancy' in vpc:
                n['tenancy'] = vpc['InstanceTenancy']
            if 'Ipv6CidrBlockAssociationSet' in vpc:
                n['ipv6_cidr'] = True
            n['dns_hostnames'] = vpc['EnableDnsHostnames']
            n['dns_support'] = vpc['EnableDnsSupport']
            vpc_net = {'amazon.aws.ec2_vpc_net': n}
            if vpc['IsDefault']:
                vpc_net.update({'check_mode': True, 'changed_when': False})
            if force_optimize and not vpc['IsDefault']:
                pre_optimized.append(vpc_net)
            else:
                vpcs.append(vpc_net)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="networks")
            if optimized:
                vpcs.append(optimized)
        return vpcs

    def create_subnets(self, force_optimize=conf.VARS_OPT_SUBNETS,
                       vars_file=True):
        subs = []
        pre_optimized = []
        for sub in self.data['subnets']:
            s = {'state': 'present'}
            s['cidr'] = sub['CidrBlock']
            s['vpc_id'] = sub['VpcId']
            if sub['AssignIpv6AddressOnCreation']:
                s['assign_instances_ipv6'] = True
            if sub['AvailabilityZone']:
                s['az'] = sub['AvailabilityZone']
            if sub['Ipv6CidrBlockAssociationSet']:
                s['ipv6_cidr'] = sub['Ipv6CidrBlockAssociationSet'][0]['Ipv6CidrBlock']
            if sub['MapPublicIpOnLaunch']:
                s['map_public'] = sub['MapPublicIpOnLaunch']
            if 'Tags' in sub:
                s['tags'] = {t['Key']: t['Value'] for t in sub['Tags']
                             if not t['Key'].startswith('aws:')}
            sub_net = {'amazon.aws.ec2_vpc_subnet': s}
            if force_optimize:
                pre_optimized.append(sub_net)
            else:
                subs.append(sub_net)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="subnets")
            if optimized:
                subs.append(optimized)
        return subs

    def create_security_groups(self, force_optimize=conf.VARS_OPT_SECGROUPS,
                               vars_file=True):
        sgs = []
        pre_optimized = []
        for secgr in self.data['secgroups']:
            sg = {'state': 'present'}
            sg['name'] = secgr['GroupName']
            sg['description'] = secgr['Description']
            sg['vpc_id'] = secgr['VpcId']
            if 'Tags' in secgr:
                sg['tags'] = {t['Key']: t['Value'] for t in secgr['Tags']
                              if not t['Key'].startswith('aws:')}
            rules = []
            for rule in secgr['IpPermissions']:
                r = {}
                r['proto'] = rule['IpProtocol']
                if 'FromPort' in rule:
                    r['from_port'] = rule['FromPort']
                if 'ToPort' in rule:
                    r['to_port'] = rule['ToPort']
                if rule['IpRanges']:
                    r['cidr_ip'] = rule['IpRanges'][0]['CidrIp']
                    if 'Description' in rule['IpRanges'][0]:
                        r['rule_desc'] = rule['IpRanges'][0]['Description']
                elif rule['Ipv6Ranges']:
                    r['cidr_ipv6'] = rule['Ipv6Ranges'][0]['CidrIpv6']
                    if 'Description' in rule['Ipv6Ranges'][0]:
                        r['rule_desc'] = rule['Ipv6Ranges'][0]['Description']
                elif rule['PrefixListIds']:
                    r['ip_prefix'] = rule['PrefixListIds'][0]['PrefixListId']
                    if 'Description' in rule['PrefixListIds'][0]:
                        r['rule_desc'] = rule['PrefixListIds'][0]['Description']
                elif rule['UserIdGroupPairs']:
                    r['group_id'] = rule['UserIdGroupPairs'][0]['GroupId']
                    if 'Description' in rule['UserIdGroupPairs'][0]:
                        r['rule_desc'] = rule['UserIdGroupPairs'][0]['Description']
                rules.append(r)
            sg['rules'] = rules
            sg_net = {'amazon.aws.ec2_group': sg}
            if force_optimize:
                pre_optimized.append(sg_net)
            else:
                sgs.append(sg_net)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="secgroups")
            if optimized:
                sgs.append(optimized)
        return sgs

    def create_routers(self, force_optimize=conf.VARS_OPT_ROUTERS,
                       vars_file=True):
        routers = []
        pre_optimized = []
        for rt in self.data['routers']:
            r = {'state': 'present'}
            if rt.get('Attachments', False):
                r['vpc_id'] = rt['Attachments'][0]['VpcId']
            else:  # amazon collection requires vpc_id for router
                continue
            if 'Tags' in rt:
                r['tags'] = {t['Key']: t['Value'] for t in rt['Tags']
                             if not t['Key'].startswith('aws:')}
            rt_net = {'amazon.aws.ec2_vpc_igw': r}
            if force_optimize:
                pre_optimized.append(rt_net)
            else:
                routers.append(rt_net)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="routers")
            if optimized:
                routers.append(optimized)
        return routers

    def create_nat_gateways(self, force_optimize=conf.VARS_OPT_NAT_GWS,
                            vars_file=True):
        ngws = []
        pre_optimized = []
        for ng in self.data['nat_gateways']:
            n = {'state': 'present'}
            n['subnet_id'] = ng['SubnetId']
            n['if_exist_do_not_create'] = True
            if 'Tags' in ng:
                n['tags'] = {t['Key']: t['Value'] for t in ng['Tags']
                             if not t['Key'].startswith('aws:')}
            n['allocation_id'] = ng['NatGatewayAddresses'][0]['AllocationId']
            ng_net = {'amazon.aws.ec2_vpc_nat_gateway': n}
            if force_optimize:
                pre_optimized.append(ng_net)
            else:
                ngws.append(ng_net)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="nat_gateways")
            if optimized:
                ngws.append(optimized)
        return ngws

    def create_route_tables(self, force_optimize=conf.VARS_OPT_ROUTE_TABLES,
                            vars_file=True):
        route_tbs = []
        pre_optimized = []
        for ro in self.data['route_tables']:
            r = {'state': 'present'}
            r['route_table_id'] = ro['RouteTableId']
            r['lookup'] = 'id'
            r['vpc_id'] = ro['VpcId']
            if ro.get('Tags'):
                r['tags'] = {t['Key']: t['Value'] for t in ro['Tags']
                             if not t['Key'].startswith('aws:')}
            r['routes'] = []
            for route in ro['Routes']:
                rt = {}
                if 'GatewayId' in route:
                    if route['GatewayId'] == 'local':
                        continue
                    if route['GatewayId'].startswith('igw-'):
                        rt['gateway_id'] = 'igw'
                        if 'DestinationCidrBlock' in route:
                            rt['dest'] = route['DestinationCidrBlock']
                        if 'DestinationIpv6CidrBlock' in route:
                            rt['dest'] = route['DestinationIpv6CidrBlock']
                if rt:
                    r['routes'].append(rt)
            if r['routes']:
                rtb_net = {'amazon.aws.ec2_vpc_route_table': r}
                if force_optimize:
                    pre_optimized.append(rtb_net)
                else:
                    route_tbs.append(rtb_net)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="route_tables")
            if optimized:
                route_tbs.append(optimized)
        return route_tbs

    def create_keypairs(self, force_optimize=conf.VARS_OPT_KEYPAIRS,
                        vars_file=True):
        keys = []
        pre_optimized = []
        for key in self.data['keypairs']:
            k = {'state': 'present'}
            k['name'] = key['KeyName']
            if key.get('Tags'):
                k['tags'] = {t['Key']: t['Value'] for t in key['Tags']
                             if not t['Key'].startswith('aws:')}
            key_pair = {'amazon.aws.ec2_key': k}
            if force_optimize:
                pre_optimized.append(key_pair)
            else:
                keys.append(key_pair)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="keypairs")
            if optimized:
                keys.append(optimized)
        return keys

    def create_servers(self, force_optimize=conf.VARS_OPT_SERVERS,
                       vars_file=True):

        servers = []
        pre_optimized = []
    #     if conf.DUMP_STORAGE:
    #         volumes_dict = {i['id']: i for i in self.data['volumes']}
    #         images_dict = {i['id']: i['name'] for i in self.data['images']}
    #     else:
    #         volumes_dict = {}
    #         images_dict = {}

        for ser in self.data['servers']:

            inst = ser['Instances'][0]
            if inst['State']['Name'] == 'terminated':
                continue
            s = {'state': inst['State']['Name']}
            s['instance_type'] = inst['InstanceType']
            s['tags'] = {t['Key']: t['Value'] for t in inst['Tags']
                         if not t['Key'].startswith('aws:')}
            s['image_id'] = inst['ImageId']
            s['security_groups'] = [sg['GroupName'] for sg in inst['SecurityGroups']]
            s['vpc_subnet_id'] = inst['SubnetId']
            s['key_name'] = inst['KeyName']
            s['availability_zone'] = inst['Placement']['AvailabilityZone']
            s['tenancy'] = inst['Placement']['Tenancy']
            s['cpu_options'] = {
                'threads_per_core': inst['CpuOptions']['ThreadsPerCore'],
                'core_count': inst['CpuOptions']['CoreCount']
            }
            s['detailed_monitoring'] = inst['Monitoring']['State'].lower() == 'enabled'
            s['ebs_optimized'] = inst['EbsOptimized']
            s['placement_group'] = inst['Placement']['GroupName']
            s['metadata_options'] = {
                'http_endpoint': inst['MetadataOptions']['HttpEndpoint'],
                'http_tokens': inst['MetadataOptions']['HttpTokens'],
                'http_put_response_hop_limit': inst['MetadataOptions']['HttpPutResponseHopLimit'],
                'instance_metadata_tags': inst['MetadataOptions']['State'],
            }

    #         s['name'] = ser['name']
    #         s['cloud'] = self.data['cloud']
    #         if value(ser, 'server', 'security_groups'):
    #             s['security_groups'] = list(
    #                 {i['name'] for i in ser['security_groups']})
    #         if 'original_name' in ser['flavor']:
    #             s['flavor'] = ser['flavor']['original_name']
    #         elif ser['flavor_id']:
    #             s['flavor'] = flavors_names[ser['flavor_id']]
    #         else:
    #             raise Exception("Flavor for server %s not found! %s" % (
    #                 ser['name'], str(ser['flavor'])))
    #         if value(ser, 'server', 'key_name'):
    #             s['key_name'] = ser['key_name']
    #         if value(ser, 'server', 'scheduler_hints'):
    #             s['scheduler_hints'] = ser['scheduler_hints']
    #         if value(ser, 'server', 'metadata'):
    #             s['meta'] = ser['metadata']
    #         if value(ser, 'server', 'config_drive'):
    #             s['config_drive'] = ser['config_drive'] == 'True'
    #         if value(ser, 'server', 'user_data'):
    #             s['userdata'] = ser['user_data']
    #         # Images and volumes
    #         if ser['image']['id']:
    #             if ser['image']['id'] in images_dict:
    #                 s['image'] = (
    #                     ser['image']['id']
    #                     if not conf.IMAGES_AS_NAMES
    #                     else images_dict[ser['image']['id']])
    #             else:
    #                 print("Image with ID=%s of server %s is not in images list" %
    #                       (ser['image']['id'], ser['name']))
    #                 continue
    #         else:
    #             # Dancing with boot volumes
    #             if conf.USE_EXISTING_BOOT_VOLUMES:
    #                 s['boot_volume'] = get_boot_volume(
    #                     ser['attached_volumes'])['id']
    #                 # s['volumes'] = [i['id'] for i in ser['attached_volumes']]
    #             elif conf.USE_SERVER_IMAGES:
    #                 meta = get_boot_volume(ser['attached_volumes'])[
    #                     'volume_image_metadata']
    #                 s['image'] = (meta['image_name']
    #                               if conf.IMAGES_AS_NAMES else meta['image_id'])
    #                 if conf.CREATE_NEW_BOOT_VOLUMES:
    #                     s['boot_from_volume'] = True
    #                     s['volume_size'] = get_boot_volume(
    #                         ser['attached_volumes'])['size']
    #         if ser.get('attached_volumes'):
    #             non_bootable_volumes = [i['id'] for i in ser['attached_volumes']
    #                                     if not volumes_dict[i['id']]['is_bootable']]
    #             if non_bootable_volumes:
    #                 s['volumes'] = non_bootable_volumes
    #         if ser.get('addresses'):
    #             if conf.NETWORK_AUTO:
    #                 # In case of DHCP just connect to networks
    #                 nics = [{"net-name": i}
    #                         for i in list(ser['addresses'].keys())]
    #                 s['nics'] = nics
    #             elif conf.STRICT_NETWORK_IPS:
    #                 s['nics'] = []
    #                 for net in list(ser['addresses'].keys()):
    #                     for ip in ser['addresses'][net]:
    #                         if ip['OS-EXT-IPS:type'] == 'fixed':
    #                             s['nics'].append(
    #                                 {'net-name': net, 'fixed_ip': ip['addr']})
    #             if conf.FIP_AUTO:
    #                 # If there are existing floating IPs only
    #                 s['auto_ip'] = has_floating(ser['addresses'])
    #             elif conf.STRICT_FIPS:
    #                 fips = [j['addr'] for i in list(ser['addresses'].values())
    #                         for j in i if j['OS-EXT-IPS:type'] == 'floating']
    #                 s['floating_ips'] = fips
            if force_optimize:
                pre_optimized.append({'amazon.aws.ec2_instance': s})
            else:
                servers.append({'amazon.aws.ec2_instance': s})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="servers")
            if optimized:
                servers.append(optimized)
        return servers


class AmazonInfo:
    """Retrieve information about Amazon cloud

    Args:
        debug (bool, optional): debug option. Defaults to False.
    """
    def __init__(self, debug=False):
        self.debug = debug
        self.data = {}
        self.ec2 = None

    def run(self):
        self.get_info()

    def get_info(self):
        self.ec2 = boto3.client('ec2')
        # pylint: disable=maybe-no-member
        if self.debug:
            boto3.set_stream_logger('boto3.resources', logging.DEBUG)
        info_matrix = {
            'networks': (conf.DUMP_NETWORKS,
                         self.ec2.describe_vpcs, 'Vpcs', const.FILE_NETWORKS),
            'subnets': (conf.DUMP_NETWORKS,
                        self.ec2.describe_subnets, 'Subnets', const.FILE_SUBNETS),
            'secgroups': (conf.DUMP_NETWORKS,
                          self.ec2.describe_security_groups, 'SecurityGroups',
                          const.FILE_SECURITY_GROUPS),
            'routers': (conf.DUMP_NETWORKS,
                        self.ec2.describe_internet_gateways, 'InternetGateways',
                        const.FILE_ROUTERS),
            'route_tables': (conf.DUMP_NETWORKS,
                             self.ec2.describe_route_tables, 'RouteTables', const.FILE_ROUTE_TBS),
            'nat_gateways': (conf.DUMP_NETWORKS,
                             self.ec2.describe_nat_gateways, 'NatGateways', const.FILE_NAT_GWS),
            'eips': (conf.DUMP_NETWORKS,
                     self.ec2.describe_network_interfaces, 'NetworkInterfaces', const.FILE_EIPS),
            'dhcpopts': (conf.DUMP_NETWORKS,
                         self.ec2.describe_dhcp_options, 'DhcpOptions', const.FILE_DHCPS),
            # 'ports': (conf.DUMP_NETWORKS, conn.network.ports, const.FILE_PORTS),
            # 'images': (conf.DUMP_STORAGE, conn.image.images, const.FILE_IMAGES),
            # 'volumes': (conf.DUMP_STORAGE, conn.volume.volumes, const.FILE_VOLUMES),
            # # 'volumes': (conf.DUMP_STORAGE, conn.block_storage.volumes, const.FILE_VOLUMES),
            # # 'floating_ips': (conf.DUMP_NETWORKS, conn.network.floating_ips, const.FILE_FIPS),
            'keypairs': (conf.DUMP_SERVERS,
                         self.ec2.describe_key_pairs, 'KeyPairs', const.FILE_KEYPAIRS),
            'servers': (conf.DUMP_SERVERS,
                        self.ec2.describe_instances, 'Reservations', const.FILE_SERVERS),
            # 'users': (conf.DUMP_IDENTITY, conn.identity.users, const.FILE_FLAVORS),
            # 'projects': (conf.DUMP_IDENTITY, conn.identity.projects, const.FILE_PROJECTS),
            # 'domains': (conf.DUMP_IDENTITY, conn.identity.domains, const.FILE_DOMAINS),
        }
        for data_type, (dump, func, key, file_name) in info_matrix.items():
            if dump:
                self.data[data_type] = func()[key]  # pylint: disable=not-callable
                if data_type == 'networks':
                    self.data[data_type] = self.complete_networks(self.data[data_type])
                self.dump2file(file_name, data_type)

        if conf.DATA_DIR_TRANSIENT:
            write_yaml(self.data, os.path.join(conf.DATA_DIR_TRANSIENT,
                                               const.FILE_ALL_DATA))

    def dump2file(self, path, data_type):
        if conf.DATA_DIR_TRANSIENT:
            write_yaml(
                self.data[data_type],
                os.path.join(conf.DATA_DIR_TRANSIENT, path))

    def complete_networks(self, data):
        for vpc in data:
            vpc['EnableDnsSupport'] = self.ec2.describe_vpc_attribute(
                Attribute='enableDnsSupport',
                VpcId=vpc['VpcId'])['EnableDnsSupport']['Value']
            vpc['EnableDnsHostnames'] = self.ec2.describe_vpc_attribute(
                Attribute='enableDnsHostnames',
                VpcId=vpc['VpcId'])['EnableDnsHostnames']['Value']
        return data
