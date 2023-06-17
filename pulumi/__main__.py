"""A Python Pulumi program"""

import pulumi
import ediri_vultr as vultr

my_instance = vultr.Instance("myInstance",
    activation_email=False,
    backups="enabled",
    backups_schedule=vultr.InstanceBackupsScheduleArgs(
        type="daily",
    ),
    ddos_protection=True,
    enable_ipv6=True,
    hostname="my-instance-hostname",
    label="my-instance-label",
    os_id=167,
    plan="vc2-1c-1gb",
    region="sea",
    tags=["my-instance-tag"])