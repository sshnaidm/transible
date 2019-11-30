#!/usr/bin/python3
import argparse
import sys
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
    parser.add_argument('--os-cloud', dest="cloud_name",
                        default="",
                        help='Openstack cloud name from clouds.yaml')
    args = parser.parse_args()
    if args.from_cloud == "openstack" and args.to == "ansible":
        if not args.cloud_name:
            print("Please provide the cloud name for Openstack")
            sys.exit(1)
        OpenstackAnsible(args.cloud_name).run()
    else:
        print("Configuration is not supported yet")


if __name__ == "__main__":
    main()
