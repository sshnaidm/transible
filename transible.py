#!/usr/bin/python3
import argparse
from plugins.os_ansible.openstack_ansible import OpenstackAnsible


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('-f', '--from', dest="from_cloud",
                        default="openstack",
                        choices=["openstack"],
                        help='Cloud type to read configuration from')
    parser.add_argument('-t', '--to', dest="to",
                        default="ansible",
                        choices=["ansible"],
                        help='Deplyment tool')
    args = parser.parse_args()
    if args.from_cloud == "openstack" and args.to == "ansible":
        OpenstackAnsible().run()
    else:
        print("Configuration is not supported yet")


if __name__ == "__main__":
    main()
