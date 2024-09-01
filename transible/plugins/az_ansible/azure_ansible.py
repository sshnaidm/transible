import os
import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient

from transible.plugins.az_ansible import config as conf
from transible.plugins.az_ansible import const
from transible.plugins.az_ansible.common import write_yaml
from transible.utils import read_yaml, optimize


class AzureAnsible:
    """Main class to generate Ansible playbooks from Azure

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
            ai = AzureInfo(debug=debug)
            ai.run()
            self.data = ai.data
        self.debug = debug
        self.az_calc = AzureAnsibleCalculation(self.data, debug=self.debug)

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
            const.FILE_RESOURCEGRPS: ('networks', self.az_calc.create_resource_groups),
            const.FILE_NETWORKS: ('networks', self.az_calc.create_vpcs),
            const.FILE_SUBNETS: ('networks', self.az_calc.create_subnets),
            const.FILE_SECURITY_GROUPS: ('networks', self.az_calc.create_security_groups),
            const.FILE_EIPS: ('networks', self.az_calc.create_public_ips),
            const.FILE_NETINF: ('networks', self.az_calc.create_network_interfaces),
            const.FILE_APP_GROUPS: ('networks', self.az_calc.create_app_secgroups),
            const.FILE_LBS: ('networks', self.az_calc.create_load_balancers),
            const.FILE_SERVERS: ('compute', self.az_calc.create_servers),
            const.FILE_AVAIL_SETS: ('compute', self.az_calc.create_availability_sets),
            const.FILE_NAT_GWS: ('networks', self.az_calc.create_nat_gateways),

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
        del_playbook = const.PLAYBOOK_DELETE
        play_matrix_del = {
            const.IDENTITY_PLAYBOOK_D: conf.DUMP_IDENTITY,
            const.COMPUTE_PLAYBOOK_D: conf.DUMP_SERVERS,
            const.STORAGE_PLAYBOOK_D: conf.DUMP_STORAGE,
            const.NET_PLAYBOOK_D: conf.DUMP_NETWORKS,
        }
        for play, dump in play_matrix_del.items():
            if dump:
                del_playbook += play
        with open(os.path.join(conf.PLAYS, "delete-playbook.yml"), "w") as f:
            f.write(del_playbook)


class AzureAnsibleCalculation:
    """Class to generate all Ansible playbooks.

    Args:
            data (dict): Azure info data to be used to generate the playbooks.
            debug (bool, optional): debug option. Defaults to False.
    """
    def __init__(self, data, debug=False):
        self.debug = debug
        self.data = data
        self.resource_group_name = '{{ resource_group }}'

    def create_resource_groups(self, force_optimize=conf.VARS_OPT_RESOURCEGRPS,
                               vars_file=True):
        rgs = []
        pre_optimized = []
        for rg in self.data['resource_groups']:
            r = {'state': '{{ state }}'}
            r['name'] = rg['name']
            r['location'] = rg['location']
            # r['tags'] = rg['tags']
            rg_net = {'azure.azcollection.azure_rm_resourcegroup': r}
            if force_optimize:
                pre_optimized.append(rg_net)
            else:
                rgs.append(rg_net)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="resource_groups")
            if optimized:
                rgs.append(optimized)
        return rgs

    def create_vpcs(self, force_optimize=conf.VARS_OPT_NETWORKS,
                    vars_file=True):
        vpcs = []
        pre_optimized = []
        for vpc in self.data['networks']:
            n = {'state': '{{ state }}'}
            n['resource_group'] = self.resource_group_name
            n['address_prefixes_cidr'] = vpc['address_space']['address_prefixes']
            if vpc.get('dhcp_options', {}).get('dns_servers'):
                n['dns_servers'] = vpc['dhcp_options']['dns_servers']
            n['name'] = vpc['name']
            # if vpc['tags']:
            #     n['tags'] = vpc['tags']

            vpc_net = {'azure.azcollection.azure_rm_virtualnetwork': n}

            if force_optimize:
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
        for net_name in self.data['subnets']:
            for sub in self.data['subnets'][net_name]:
                s = {'state': '{{ state }}'}
                s['resource_group'] = self.resource_group_name
                s['name'] = sub['name']
                s['virtual_network_name'] = net_name
                if sub.get('address_prefix'):
                    s['address_prefix_cidr'] = sub['address_prefix']
                if sub.get('address_prefixes'):
                    s['address_prefixes_cidr'] = sub['address_prefixes']
                sub_net = {'azure.azcollection.azure_rm_subnet': s}
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
        for secgr in self.data['security_groups']:
            sg = {'state': '{{ state }}'}
            sg['resource_group'] = self.resource_group_name
            sg['name'] = secgr['name']
            rules = []
            for rule in secgr['security_rules']:
                r = {}
                r['name'] = rule['name']
                r['protocol'] = rule['protocol'].capitalize()
                r['access'] = rule['access']
                r['direction'] = rule['direction']
                r['priority'] = rule['priority']
                if rule.get('description'):
                    r['description'] = rule['description']
                if rule['source_address_prefix']:
                    r['destination_address_prefix'] = rule['destination_address_prefix']
                if rule['destination_address_prefixes']:
                    r['destination_address_prefix'] = rule['destination_address_prefixes']
                if rule.get('destination_application_security_groups'):
                    r['destination_application_security_groups'] = rule['destination_application_security_groups']
                if rule['destination_port_range']:
                    r['destination_port_range'] = rule['destination_port_range']
                if rule['destination_port_ranges']:
                    r['destination_port_range'] = rule['destination_port_ranges']
                if rule['source_port_range']:
                    r['source_port_range'] = rule['source_port_range']
                if rule['source_port_ranges']:
                    r['source_port_range'] = rule['source_port_ranges']
                if rule['source_address_prefix']:
                    r['source_address_prefix'] = rule['source_address_prefix']
                if rule['source_address_prefixes']:
                    r['source_address_prefix'] = rule['source_address_prefixes']
                if rule.get('source_application_security_groups'):
                    r['source_application_security_groups'] = rule['source_application_security_groups']
                rules.append(r)
            sg['rules'] = rules
            sg_net = {'azure.azcollection.azure_rm_securitygroup': sg}
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

    def create_public_ips(self, force_optimize=conf.VARS_OPT_IP,
                          vars_file=True):
        pubips = []
        pre_optimized = []
        for ip in self.data['public_ips']:
            ni = {'state': '{{ state }}'}
            ni['resource_group'] = self.resource_group_name
            ni['name'] = ip['name']
            ni['allocation_method'] = ip['public_ip_allocation_method']
            ni['version'] = ip['public_ip_address_version'].lower()
            if ip.get('dns_settings', {}).get('domain_name_label'):
                ni['domain_name'] = ip['dns_settings']['domain_name_label']
            if ip.get("sku"):
                ni['sku'] = ip['sku']['name']
            new_ips = {'azure.azcollection.azure_rm_publicipaddress': ni}
            if force_optimize:
                pre_optimized.append(new_ips)
            else:
                pubips.append(new_ips)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="public_ips")
            if optimized:
                pubips.append(optimized)
        return pubips

    def create_network_interfaces(self, force_optimize=conf.VARS_OPT_NETINTS,
                                  vars_file=True):
        netints = []
        pre_optimized = []
        for netin in self.data['network_interfaces']:
            n = {'state': '{{ state }}'}
            n['resource_group'] = self.resource_group_name
            n['name'] = netin['name']
            ip_conf = netin['ip_configurations'][0]
            subnet = ip_conf['subnet']['id'].split("subnets/")[1]
            vpc = ip_conf['subnet']['id'].split("virtualNetworks/")[1].split("/")[0]
            n['subnet'] = subnet
            n['virtual_network'] = vpc
            # n['create_with_security_group'] = False
            if netin.get('dns_settings'):
                n['dns_servers'] = netin['dns_settings']['dns_servers']
            if netin.get('enable_accelerated_networking'):
                n['enable_accelerated_networking'] = netin['enable_accelerated_networking']
            if netin.get('enable_ip_forwarding'):
                n['enable_ip_forwarding'] = netin['enable_ip_forwarding']
            n['security_group'] = netin['network_security_group']['id'].split("networkSecurityGroups/")[1]
            ip_configs = []
            for ip_conf in netin['ip_configurations']:
                ip = {}
                ip['name'] = ip_conf['name']
                if ip_conf.get('private_ip_address'):
                    ip['private_ip_address'] = ip_conf['private_ip_address']
                if ip_conf.get('private_ip_address_version'):
                    ip['private_ip_address_version'] = ip_conf['private_ip_address_version']
                if ip_conf.get('private_ip_allocation_method'):
                    ip['private_ip_allocation_method'] = ip_conf['private_ip_allocation_method']

                if ip_conf.get('public_ip_address'):
                    ip['public_ip_address_name'] = ip_conf['public_ip_address']['id'].split("publicIPAddresses/")[1]

                if ip_conf.get('primary') is not None:
                    ip['primary'] = ip_conf['primary']

                if ip_conf.get('application_gateway_backend_address_pools'):
                    ip['application_gateway_backend_address_pools'] = [
                        i['id'] for i in ip_conf['application_gateway_backend_address_pools']]
                if ip_conf.get('load_balancer_backend_address_pools'):
                    ip['load_balancer_backend_address_pools'] = [
                        i['id'] for i in ip_conf['load_balancer_backend_address_pools']]
                    # replace resource group
                    pools = []
                    for i in ip['load_balancer_backend_address_pools']:
                        rgroup = i.split("/resourceGroups/")[1].split("/")[0]
                        newgrp = i.replace(rgroup, self.resource_group_name)
                        pools.append(newgrp)
                    ip['load_balancer_backend_address_pools'] = pools
                if ip_conf.get('application_security_groups'):
                    ip['application_security_groups'] = [
                        i['id'].split('applicationSecurityGroups/')[1] for i in ip_conf['application_security_groups']]
                ip_configs.append(ip)
            n['ip_configurations'] = ip_configs
            net_ints = {'azure.azcollection.azure_rm_networkinterface': n}
            if force_optimize:
                pre_optimized.append(net_ints)
            else:
                netints.append(net_ints)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="network_interfaces")
            if optimized:
                netints.append(optimized)
        return netints

    def create_nat_gateways(self, force_optimize=conf.VARS_OPT_NAT_GWS,
                            vars_file=True):
        ngws = []
        pre_optimized = []
        for ng in self.data['nat_gateways']:
            n = {'state': '{{ state }}'}
            n['resource_group'] = self.resource_group_name
            n['name'] = ng['name']
            n['public_ip_addresses'] = [i['id'].split("/publicIPAddresses/")[1] for i in ng['public_ip_addresses']]
            n['idle_timeout_in_minutes'] = ng['idle_timeout_in_minutes']
            n['sku'] = ng['sku']['name']
            ngw = {'azure.azcollection.azure_rm_natgateway': n}
            if force_optimize:
                pre_optimized.append(ngw)
            else:
                ngws.append(ngw)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="nat_gateways")
            if optimized:
                ngws.append(optimized)
        return ngws

    def create_app_secgroups(self, force_optimize=conf.VARS_OPT_APPSECGROUPS,
                             vars_file=True):
        appscgps = []
        pre_optimized = []
        for apps in self.data['application_security_groups']:
            a = {'state': '{{ state }}'}
            a['resource_group'] = self.resource_group_name
            a['name'] = apps['name']
            app_group = {'azure.azcollection.azure_rm_applicationsecuritygroup': a}
            if force_optimize:
                pre_optimized.append(app_group)
            else:
                appscgps.append(app_group)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="application_security_groups")
            if optimized:
                appscgps.append(optimized)
        return appscgps

    def create_load_balancers(self, force_optimize=conf.VARS_OPT_LBS,
                              vars_file=True):
        lbs = []
        pre_optimized = []
        for lb in self.data['load_balancers']:
            newlb = {'state': '{{ state }}'}
            newlb['resource_group'] = self.resource_group_name
            newlb['name'] = lb['name']
            newlb['backend_address_pools'] = [{'name': i['name']} for i in lb['backend_address_pools']]
            fr_cfg = []
            for frip in lb['frontend_ip_configurations']:
                fr = {}
                fr['name'] = frip['name']
                if frip.get('public_ip_address'):
                    fr['public_ip_address'] = frip['public_ip_address']['id'].split("publicIPAddresses/")[1]
                if frip.get('private_ip_address'):
                    fr['private_ip_address'] = frip['private_ip_address']
                if frip.get('private_ip_allocation_method'):
                    fr['private_ip_allocation_method'] = frip['private_ip_allocation_method']

                if frip.get('subnet'):
                    fr = frip['subnet']['id'].split("subnets/")[1]
                fr_cfg.append(fr)
            newlb['frontend_ip_configurations'] = fr_cfg
            if lb['inbound_nat_rules']:
                natrules = []
                for rule in lb['inbound_nat_rules']:
                    nr = {}
                    nr['name'] = rule['name']
                    nr['protocol'] = rule['protocol']
                    nr['frontend_ip_configuration'] = rule[
                        'frontend_ip_configuration']['id'].split("/frontendIPConfigurations/")[1]
                    nr['frontend_port'] = rule['frontend_port']
                    nr['enable_floating_ip'] = rule['enable_floating_ip']
                    nr['backend_port'] = rule['backend_port']
                    nr['enable_tcp_reset'] = rule['enable_tcp_reset']
                    nr['idle_timeout'] = rule['idle_timeout_in_minutes']
                    natrules.append(nr)
                newlb['inbound_nat_rules'] = natrules
            if lb['inbound_nat_pools']:
                natpools = []
                for pool in lb['inbound_nat_pools']:
                    np = {}
                    np['name'] = pool['name']
                    np['protocol'] = pool['protocol']
                    np['frontend_ip_configuration_name'] = pool['frontend_ip_configuration']['id'].split(
                        "/frontendIPConfigurations/")[1]
                    np['frontend_port_range_start'] = pool['frontend_port_range_start']
                    np['frontend_port_range_end'] = pool['frontend_port_range_end']
                    np['backend_port'] = pool['backend_port']
                    natpools.append(np)
                newlb['inbound_nat_pools'] = natpools
            if lb['load_balancing_rules']:
                rul_cfgs = []
                for rule in lb['load_balancing_rules']:
                    rcfg = {}
                    rcfg['name'] = rule['name']
                    rcfg['backend_address_pool'] = rule['backend_address_pool']['id'].split("/backendAddressPools/")[1]
                    rcfg['backend_port'] = rule['backend_port']
                    rcfg['frontend_port'] = rule['frontend_port']
                    rcfg['enable_floating_ip'] = rule['enable_floating_ip']
                    rcfg['frontend_ip_configuration'] = rule['frontend_ip_configuration']['id'].split(
                        "/frontendIPConfigurations/")[1]
                    rcfg['idle_timeout'] = rule['idle_timeout_in_minutes']
                    rcfg['load_distribution'] = rule['load_distribution']
                    rcfg['protocol'] = rule['protocol']
                    rcfg['probe'] = rule['probe']['id'].split("/probes/")[1]
                    rul_cfgs.append(rcfg)
                newlb['load_balancing_rules'] = rul_cfgs
            if lb['probes']:
                probes_cfg = []
                for probe in lb['probes']:
                    prb = {}
                    prb['name'] = probe['name']
                    prb['port'] = probe['port']
                    prb['protocol'] = probe['protocol']
                    prb['interval'] = probe['interval_in_seconds']
                    if probe.get('request_path'):
                        prb['request_path'] = probe['request_path']
                    prb['fail_count'] = probe['number_of_probes']
                    probes_cfg.append(prb)
                newlb['probes'] = probes_cfg
            newlb['sku'] = lb['sku']['name']
            lb_grp = {'azure.azcollection.azure_rm_loadbalancer': newlb}
            if force_optimize:
                pre_optimized.append(lb_grp)
            else:
                lbs.append(lb_grp)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="load_balancers")
            if optimized:
                lbs.append(optimized)
        return lbs

    def create_availability_sets(self, force_optimize=conf.VARS_OPT_AVAILSETS,
                                 vars_file=True):
        avsets = []
        pre_optimized = []
        for avset in self.data['availability_sets']:
            a = {'state': '{{ state }}'}
            a['resource_group'] = self.resource_group_name
            a['name'] = avset['name']
            a['platform_fault_domain_count'] = avset['platform_fault_domain_count']
            a['platform_update_domain_count'] = avset['platform_update_domain_count']
            a['sku'] = avset['sku']['name']
            avset_grp = {'azure.azcollection.azure_rm_availabilityset': a}
            if force_optimize:
                pre_optimized.append(avset_grp)
            else:
                avsets.append(avset_grp)
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="availability_sets")
            if optimized:
                avsets.append(optimized)
        return avsets

    def create_servers(self, force_optimize=conf.VARS_OPT_SERVERS,
                       vars_file=True):
        servers = []
        pre_optimized = []
        for ser in self.data['vms']:
            s = {'state': '{{ state }}'}
            s['resource_group'] = self.resource_group_name
            s['name'] = ser['name']
            s['vm_size'] = ser['hardware_profile']['vm_size']
            img = {}
            img['publisher'] = ser['storage_profile']['image_reference']['publisher']
            img['offer'] = ser['storage_profile']['image_reference']['offer']
            img['sku'] = ser['storage_profile']['image_reference']['sku']
            img['version'] = ser['storage_profile']['image_reference']['version']
            s['image'] = img
            s['admin_username'] = ser['os_profile']['admin_username']
            if ser['os_profile'].get('admin_password'):
                s['admin_password'] = ser['os_profile']['admin_password']
            if ser.get('availability_set'):
                s['availability_set'] = ser['availability_set']['id'].split("/availabilitySets/")[1]
            s['boot_diagnostics'] = ser['diagnostics_profile']['boot_diagnostics']
            s['created_nsg'] = False
            if ser.get('user_data'):
                s['custom_data'] = ser['os_profile']['user_data']
            if ser.get('data_disks'):
                dd = []
                for disk in ser['data_disks']:
                    d = {}
                    d['name'] = disk['name']
                    d['caching'] = disk['caching']
                    d['create_option'] = disk['create_option']
                    d['disk_size_gb'] = disk['disk_size_gb']
                    d['lun'] = disk['lun']
                    d['managed_disk_type'] = disk['managed_disk']['storage_account_type']
                    dd.append(d)
                s['data_disks'] = dd
            if ser.get('eviction_policy'):
                s['eviction_policy'] = ser['eviction_policy']
            if ser['os_profile'].get(
                    'linux_configuration', {}).get(
                        'disable_password_authentication') is not None:
                s['linux_config'] = {
                    'disable_password_authentication': ser['os_profile'][
                        'linux_configuration']['disable_password_authentication']
                }
            if ser['os_profile'].get('linux_configuration', {}).get('ssh'):
                s['ssh_public_keys'] = ser['os_profile']['linux_configuration']['ssh']['public_keys']
            if 'storage_account_type' in ser['storage_profile']['os_disk']['managed_disk']:
                s['managed_disk_type'] = ser['storage_profile']['os_disk']['managed_disk']['storage_account_type']
            if ser.get('billing_profile'):
                s['max_price'] = ser['billing_profile']['max_price']
            s['network_interface_names'] = [
                i['id'].split("/networkInterfaces/")[1] for i in ser['network_profile']['network_interfaces']]
            s['os_disk_caching'] = ser['storage_profile']['os_disk']['caching']
            s['os_disk_name'] = ser['storage_profile']['os_disk']['name']
            if 'disk_size_gb' in ser['storage_profile']['os_disk']:
                s['os_disk_size_gb'] = ser['storage_profile']['os_disk']['disk_size_gb']
            s['os_type'] = ser['storage_profile']['os_disk']['os_type']
            if 'plan' in ser:
                s['plan'] = ser['plan']
            if 'priority' in ser and ser['priority'] != 'Regular':
                s['priority'] = ser['priority']
            if 'proximity_placement_group' in ser:
                s['proximity_placement_group'] = ser['proximity_placement_group']['id'].split(
                    "/proximityPlacementGroups/")[1]
            if 'security_profile' in ser:
                s['security_profile'] = ser['security_profile']
            if 'identity' in ser:
                s['vm_identity'] = ser['identity']['type']
            if ser['os_profile'].get('windows_configuration'):
                s['windows_config'] = {
                    'enable_automatic_updates': ser['os_profile']['windows_configuration']['enable_automatic_updates'],
                    'provision_vm_agent': ser['os_profile']['windows_configuration']['provision_vm_agent']
                }
            if 'zones' in ser:
                s['zones'] = ser['zones']
            if ser['os_profile'].get('windows_configuration', {}).get('win_rm'):
                s['winrm'] = ser['os_profile']['windows_configuration']['win_rm']['listeners'][0]

            if force_optimize:
                pre_optimized.append({'azure.azcollection.azure_rm_virtualmachine': s})
            else:
                servers.append({'azure.azcollection.azure_rm_virtualmachine': s})
        if force_optimize:
            optimized = optimize(
                pre_optimized,
                use_vars=vars_file,
                var_name="servers")
            if optimized:
                servers.append(optimized)
        return servers


class AzureInfo:
    """Retrieve information about Azure cloud

    Args:
        debug (bool, optional): debug option. Defaults to False.
    """
    def __init__(self, debug=False):
        self.debug = debug
        self.data = {}
        credential = DefaultAzureCredential()
        subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", os.environ.get("ARM_SUBSCRIPTION_ID"))
        if subscription_id is None:
            raise ValueError("AZURE_SUBSCRIPTION_ID environment variable not set.")
        self.resource_group_name = os.environ.get("AZURE_RESOURCE_GROUP")
        if self.resource_group_name is None:
            raise ValueError("AZURE_RESOURCE_GROUP environment variable not set. It should match resource group name.")
        self.network_client = NetworkManagementClient(credential, subscription_id)
        self.resource_client = ResourceManagementClient(credential, subscription_id)
        self.compute_client = ComputeManagementClient(credential, subscription_id)

    def run(self):
        self.get_info()

    def get_info(self):

        if self.debug:
            logging.basicConfig(level=logging.DEBUG)  # pylint: disable=unexpected-keyword-arg
        iters = {
            "resource_groups": (
                True,
                [r for r in self.resource_client.resource_groups.list() if r.name == self.resource_group_name],
                const.FILE_RESOURCEGRPS
            ),
            "networks": (conf.DUMP_NETWORKS, self.network_client.virtual_networks.list(
                self.resource_group_name), const.FILE_NETWORKS),
            "security_groups": (conf.DUMP_NETWORKS, self.network_client.network_security_groups.list(
                self.resource_group_name), const.FILE_SECURITY_GROUPS),
            "public_ips": (conf.DUMP_NETWORKS, self.network_client.public_ip_addresses.list(
                self.resource_group_name), const.FILE_EIPS),
            "network_interfaces": (conf.DUMP_NETWORKS, self.network_client.network_interfaces.list(
                self.resource_group_name), const.FILE_NETINF),
            "application_security_groups": (conf.DUMP_NETWORKS, self.network_client.application_security_groups.list(
                self.resource_group_name), const.FILE_APP_GROUPS),
            "load_balancers": (conf.DUMP_NETWORKS, self.network_client.load_balancers.list(
                self.resource_group_name), const.FILE_LBS),
            "subnets": (conf.DUMP_NETWORKS, self.network_client.virtual_networks.list(
                self.resource_group_name), const.FILE_SUBNETS),
            "nat_gateways": (conf.DUMP_NETWORKS, self.network_client.nat_gateways.list(
                self.resource_group_name), const.FILE_NAT_GWS),
            "availability_sets": (conf.DUMP_SERVERS, self.compute_client.availability_sets.list(
                self.resource_group_name), const.FILE_KEYPAIRS),
            "vms": (conf.DUMP_SERVERS, self.compute_client.virtual_machines.list(
                self.resource_group_name), const.FILE_SERVERS),
        }

        for data_type, (dump, iterator, file_name) in iters.items():
            if dump:

                if data_type == 'subnets':
                    self.data[data_type] = {net['name']: [
                        subnet.as_dict() for subnet in self.network_client.subnets.list(
                            self.resource_group_name, net['name'])
                    ] for net in self.data['networks']}
                else:
                    self.data[data_type] = [i.as_dict() for i in iterator]
                self.dump2file(file_name, data_type)

        if conf.DATA_DIR_TRANSIENT:
            write_yaml(self.data, os.path.join(conf.DATA_DIR_TRANSIENT,
                                               const.FILE_ALL_DATA))

    def dump2file(self, path, data_type):
        if conf.DATA_DIR_TRANSIENT:
            write_yaml(
                self.data[data_type],
                os.path.join(conf.DATA_DIR_TRANSIENT, path))
