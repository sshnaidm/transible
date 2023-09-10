import pytest
import yaml
from transible.plugins.az_ansible.azure_ansible import AzureAnsibleCalculation


class TestAZAnsible:

    @pytest.fixture(autouse=True)
    def setup_class(self):
        with open("test_data/az_data.yml") as f:
            self.data = yaml.safe_load(f)
        self.data['cloud'] = "test-cloud"
        self.a = AzureAnsibleCalculation(self.data)
        yield

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_vpcs(self, force_optimize, vars_file):
        self.a.create_vpcs(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_subnets(self, force_optimize, vars_file):
        self.a.create_subnets(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_public_ips(self, force_optimize, vars_file):
        self.a.create_public_ips(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_security_groups(self, force_optimize, vars_file):
        self.a.create_security_groups(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_resource_groups(self, force_optimize, vars_file):
        self.a.create_resource_groups(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_network_interfaces(self, force_optimize, vars_file):
        self.a.create_network_interfaces(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_app_secgroups(self, force_optimize, vars_file):
        self.a.create_app_secgroups(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_load_balancers(self, force_optimize, vars_file):
        self.a.create_load_balancers(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_servers(self, force_optimize, vars_file):
        self.a.create_servers(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_availability_sets(self, force_optimize, vars_file):
        self.a.create_availability_sets(force_optimize=force_optimize, vars_file=vars_file)
