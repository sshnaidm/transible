class AmazonAnsible:
    """Main class to generate Ansible playbooks from Amazon

    Args:
        debug (bool, optional): debug option. Defaults to False.
        from_file (str, optional): Optional file with all data. Defaults to ''.
    """


class AmazonAnsibleCalculation:
    """Class to generate all Ansible playbooks.

    Args:
            data (dict): Amazon info data to be used to generate the playbooks.
            debug (bool, optional): debug option. Defaults to False.
    """
    def __init__(self, data, debug=False):
        self.debug = debug
        self.data = data


class AmazonInfo:
    """Retrieve information about Amazon cloud

    Args:
        debug (bool, optional): debug option. Defaults to False.
    """
    def __init__(self, debug=False):
        self.debug = debug
        self.data = {}
