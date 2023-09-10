import os

from transible.utils import str2bool

PREFIX = "TRANSIBLE_"
INPUT_DATA_DIR = ""
DATA_DIR_TRANSIENT = "./az_cloud_data"


# # Paths config
# Path to playbook
PLAYS = os.environ.get(
    PREFIX + "PLAYS", os.path.join(os.path.curdir, "az_generated_playbooks"))
# Path to variables file
VARS_PATH = os.environ.get(
    PREFIX + "VARS_PATH", os.path.join(PLAYS, "vars", "main.yml"))

# Plugin config
DUMP_NETWORKS = str2bool(os.environ.get(PREFIX + "DUMP_NETWORKS", True))
DUMP_STORAGE = str2bool(os.environ.get(PREFIX + "DUMP_STORAGE", False))
DUMP_SERVERS = str2bool(os.environ.get(PREFIX + "DUMP_SERVERS", True))
DUMP_IDENTITY = str2bool(os.environ.get(PREFIX + "DUMP_IDENTITY", False))

# # Variables optimization configuration
# Set to True any of current variables to have all date for a specific resource
# in vars/ and not in playbook.
VARS_OPT_NETWORKS = False
VARS_OPT_SUBNETS = False
VARS_OPT_IP = False
VARS_OPT_APPSECGROUPS = False
VARS_OPT_LBS = False
VARS_OPT_SECGROUPS = True
VARS_OPT_SERVERS = False
VARS_OPT_NETINTS = False
VARS_OPT_RESOURCEGRPS = True
VARS_OPT_AVAILSETS = False
