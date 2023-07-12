# Ansible Cisco Small Bussiness Switches (SMB) module

Ansible Galaxy module for Cisco SMB switches - SG300, SG500, SG350, SG550, CBS350

## Install

```
ansible-galaxy collection install community.ciscosmb
```

## Usage examples

Tested on devices:
* SG350-10-K9
* SG350-28-K9
* SG500-52-K9
* SG550X-24MP-K9
* CBS350-24P-4G
* SG550X-48 stack

Tested on Python versions:
* 3.6
* 3.7
* 3.8
* 3.9
* 3.10

For your tests or quick startup use files form repository: [cismosmb_inventory_template.yml](./ciscosmb_inventory_template.yml), [cismosmb_gather_facts.yml](./ciscosmb_gather_facts.yml),  [cismosmb_commands.yml](./ciscosmb_commands.yml) .

Prepare your inventory file - copy file [cismosmb_inventory_template.yml](./ciscosmb_inventory_template.yml) to `cismosmb_inventory.yml` and make your changes.

Then you can run

```
ansible-playbook -i ciscosmb_inventory.yml cismosmb_gather_facts.yml
```
or
```
ansible-playbook -i ciscosmb_inventory.yml cismosmb_commands.yml
```

## Developement

### Setup environment

```
git clone https://github.com/ansible-collections/community.ciscosmb ansible_collections/community/ciscosmb
git clone --depth=1 --single-branch https://github.com/ansible-collections/ansible.netcommon.git ansible_collections/ansible/netcommon

cd ansible_collections/community/ciscosmb

python3 -m venv .venv
. .venv/bin/activate

pip install ansible
pip install -r requirements-dev.txt
pip install -r tests/unit/requirements.txt

```

### Develop 

```
cd ansible_collections/community/ciscosmb
git pull
. .venv/bin/activate

# edit files
vim file
cp changelogs/fragments/.keep changelogs/fragments/featureXYZ.yml
vim changelogs/fragments/featureXYZ.yml

# test your changes see "Testing"

git commit -m "xxx" file
```

### Testing

```
cd ansible_collections/community/ciscosmb
. .venv/bin/activate

# PY="--python 3.8" # set your version or unset
METHOD="--docker" # or --local if you have no Docker installed
ansible-test sanity ${METHOD} ${PY}  \
    && ansible-test units  ${METHOD} ${PY} \
    && rm -f ./community-ciscosmb-*.tar.gz  \
    && ansible-galaxy collection build -v --force  \
    && export GALAXY_IMPORTER_CONFIG=./galaxy-importer.cfg  \
    && python3 -m galaxy_importer.main ./community-ciscosmb-*.tar.gz  \
    && rm -f ./community-ciscosmb-*.tar.gz
```

### Release 

```
cd ansible_collections/community/ciscosmb
git pull
. .venv/bin/activate

# edit version x.y.z. in galaxy.yml
vim galaxy.yml

# edit changelog fragments (template in changelogs/fragments/.keep)
cp changelogs/fragments/.keep changelogs/fragments/release-x.y.z.yml
vim changelogs/fragments/fragment.yml

# change and generate CHANGELOG.rst
antsibull-changelog lint -v
antsibull-changelog release -v

git commit -m "version bump to x.y.z" .
git tag x.y.z
git push 
```

## Releasing, Versioning and Deprecation

See [RELEASE_POLICY.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/RELEASE_POLICY.md)

## Code of Conduct

See [CODE_OF_CONDUCT.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/CODE_OF_CONDUCT.md)

## Contributing

See [CONTRIBUTING.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/CONTRIBUTING.md)
