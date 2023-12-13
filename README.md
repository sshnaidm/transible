# Transible

## Convert existing cloud configuration to Ansible playbooks

In many infrastructure projects, dealing with existing cloud resources is a common scenario. Whether you've set up resources manually in your cloud provider's console or CLI, or used infrastructure as code tools like Terraform or AWS CloudFormation, Transible is here to help you adopt and manage those resources seamlessly.

### Supported Cloud Providers
Transible currently supports OpenStack, Azure, and Amazon AWS. Please note that the product is still in development, with ongoing enhancements and additional cloud provider support planned.

Run for Openstack:

```bash
./transible.py --os-cloud my-cloud-name --from openstack --to ansible
```

where `my-cloud-name` is your cloud name in [clouds.yaml](https://docs.openstack.org/python-openstackclient/train/configuration/index.html#configuration-files)

Run for Amazon AWS (make sure your credentials are in `~/.aws/config`):

```bash
./transible.py --from aws --to ansible
```

Or specify the AWS profile as environment variable:

```bash
AWS_PROFILE=readonly ./transible.py --from aws --to ansible
```

Run for Azure:

```bash
./transible.py --from azure --to ansible
```

## Demo

![Trabsible Demo](https://github.com/sshnaidm/transible/raw/master/transible-demo.gif)
