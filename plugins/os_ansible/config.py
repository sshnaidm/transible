import os


def str2bool(x):
    if isinstance(x, bool):
        return x
    if x in ['True', 'true', 1, 'T', 't', '1']:
        return True
    if x in ['False', 'false', 0, 'F', 'f', '0']:
        return False
    raise Exception("Please pass False or True instead of %s" % x)


PREFIX = "TRANSIBLE_"

# Plugin config
DUMP_NETWORKS = str2bool(os.environ.get(PREFIX + "DUMP_NETWORKS", True))
DUMP_STORAGE = str2bool(os.environ.get(PREFIX + "DUMP_STORAGE", True))
DUMP_SERVERS = str2bool(os.environ.get(PREFIX + "DUMP_SERVERS", True))

# Paths config
PLAYS = os.environ.get(
    PREFIX + "PLAYS", os.path.join(os.path.curdir, "transible"))
VARS_PATH = os.environ.get(
    PREFIX + "VARS_PATH", os.path.join(PLAYS, "vars", "main.yml"))

# Storage config
SKIP_UNNAMED_VOLUMES = str2bool(os.environ.get(
    PREFIX + "SKIP_UNNAMED_VOLUMES", True))
IMAGES_AS_NAMES = str2bool(os.environ.get(PREFIX + "IMAGES_AS_NAMES", True))
USE_SERVER_IMAGES = str2bool(os.environ.get(PREFIX + "USE_SERVER_IMAGES", True))
CREATE_NEW_BOOT_VOLUMES = str2bool(os.environ.get(
    PREFIX + "CREATE_NEW_BOOT_VOLUMES", False))
USE_EXISTING_BOOT_VOLUMES = str2bool(os.environ.get(
    PREFIX + "USE_EXISTING_BOOT_VOLUMES", False))

# Network config
NETWORK_AUTO = str2bool(os.environ.get(PREFIX + "NETWORK_AUTO", False))
FIP_AUTO = str2bool(os.environ.get(PREFIX + "FIP_AUTO", True))
STRICT_FIPS = not FIP_AUTO
STRICT_NETWORK_IPS = not NETWORK_AUTO
