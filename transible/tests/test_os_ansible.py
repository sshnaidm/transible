import pytest
import yaml
from transible.plugins.os_ansible.openstack_ansible import OpenstackCalculation


class TestOSAnsible:

    @pytest.fixture(autouse=True)
    def setup_class(self):
        with open("test_data/all_data.yml") as f:
            self.data = yaml.safe_load(f)
        self.data['cloud'] = "test-cloud"
        self.o = OpenstackCalculation(self.data)
        yield

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_networks(self, force_optimize, vars_file):
        self.o.create_networks(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_projects(self, force_optimize, vars_file):
        self.o.create_projects(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_domains(self, force_optimize, vars_file):
        self.o.create_domains(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_users(self, force_optimize, vars_file):
        self.o.create_users(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_flavors(self, force_optimize, vars_file):
        self.o.create_flavors(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_subnets(self, force_optimize, vars_file):
        self.o.create_subnets(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_security_groups(self, force_optimize, vars_file):
        self.o.create_security_groups(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_routers(self, force_optimize, vars_file):
        self.o.create_routers(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_servers(self, force_optimize, vars_file):
        self.o.create_servers(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_keypairs(self, force_optimize, vars_file):
        self.o.create_keypairs(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_volumes(self, force_optimize, vars_file):
        self.o.create_volumes(force_optimize=force_optimize, vars_file=vars_file)

    @pytest.mark.parametrize(
        "force_optimize,vars_file",
        [(True, True), (True, False), (False, False)],
        ids=["optimize_and_vars_file", "optimize_no_vars_file", "no_optimize"]
    )
    def test_create_images(self, force_optimize, vars_file):
        self.o.create_images(force_optimize=force_optimize, vars_file=vars_file)
