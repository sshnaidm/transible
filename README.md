# Transible

Convert existing cloud configuration to ansible playbooks
Currently Openstack and Amazon AWS are supported only and the product is under development

Run for Openstack:
```bash
./transible.py --os-cloud my-cloud-name --from openstack --to ansible
```
where `my-cloud-name` is your cloud name in [clouds.yaml](https://docs.openstack.org/python-openstackclient/train/configuration/index.html#configuration-files)

Run for Amazon AWS (make sure your credentials are in `~/.aws/config`):
```bash
./transible.py --from aws --to ansible
```

## Demo

[![asciicast](https://asciinema.org/a/Wsad95zocPJIMp4bJV0dnklaA.svg)](https://asciinema.org/a/Wsad95zocPJIMp4bJV0dnklaA)
