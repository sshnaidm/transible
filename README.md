# Transible

Convert existing cloud configuration to ansible playbooks
Currently Openstack is supported only and the product is under heavy development

Run:
```bash
./transible.py --os-cloud my-cloud-name
```
where `my-cloud-name` is your cloud name in [clouds.yaml](https://docs.openstack.org/python-openstackclient/train/configuration/index.html#configuration-files)
