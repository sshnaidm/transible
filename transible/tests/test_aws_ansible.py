import pytest
import yaml
from transible.plugins.aws_ansible.amazon_ansible import AmazonAnsibleCalculation


class TestAWSAnsible:

    @pytest.fixture(autouse=True)
    def setup_class(self):
        with open("test_data/aws_data.yml") as f:
            self.data = yaml.safe_load(f)
        self.data['cloud'] = "test-cloud"
        self.a = AmazonAnsibleCalculation(self.data)
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
    def test_create_security_groups(self, force_optimize, vars_file):
        self.a.create_security_groups(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_routers(self, force_optimize, vars_file):
        self.a.create_routers(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_nat_gateways(self, force_optimize, vars_file):
        self.a.create_nat_gateways(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_route_tables(self, force_optimize, vars_file):
        self.a.create_route_tables(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_keypairs(self, force_optimize, vars_file):
        self.a.create_keypairs(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_servers(self, force_optimize, vars_file):
        self.a.create_servers(force_optimize=force_optimize, vars_file=vars_file)
