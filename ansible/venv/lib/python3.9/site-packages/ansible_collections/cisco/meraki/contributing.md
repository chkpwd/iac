# Contributing

Contributions are welcome, and they are greatly appreciated! This is a one man show
so help is fantastic!

You can contribute in many ways:

## Types of Contributions

### Report Bugs

Report bugs at https://github.com/CiscoDevNet/ansible-meraki/issues. 

### Fix Bugs or Complete Enhancements

Look through the GitHub issues for bugs. Anything without a pull request associated is
open.

### Submit Feedback

Request new features at https://github.com/CiscoDevNet/ansible-meraki/issues

If you are proposing a feature:

- Explain in detail how it would work.
- Keep the scope as narrow as possible, to make it easier to implement.
- Remember that this is a volunteer-driven project, and that contributions are welcome :)

## Get Started!

Ready to contribute some code? Here's how to set up `cisco.meraki` for local development.

1. Install Python 3.8 or higher, along with Ansible

   Newer versions of Ansible require 3.8 so please target those versions.

2. Fork the `cisco.meraki` repo on GitHub

3. Clone your fork locally, using a special directory name so that Ansible understands it as a collection:

```
$ mkdir -p ansible_collections/meraki
$ git clone https://github.com/your-username/ansible-meraki.git ansible_collections/cisco/meraki/
```

4. Create a branch for local development

```
$ cd ansible_collections/cisco/meraki
$ git checkout -b name-of-your-bugfix-or-feature
```

5. Make your changes in the new branch

   You can test any changes by developing integration tests. These are in the `tests/integration/targets/module_name` directory.

6. Setup integration test Meraki variables template

   If integration tests need to be run. Copy the `tests/integration/inventory.networking.template` file to `tests/integration/inventory.networking` and fill out the values. This should never be committed into git.

7. Execute integration tests

```
$ ansible-test network-integration --allow-unsupported module_name
```

8. When you're done making changes, check that your changes pass `ansible-test sanity`:

```
$ ansible-test sanity --local
```
9. Commit your changes and push your branch to GitHub:

```
$ git add -A
$ git commit -m "Your detailed description of your changes."
$ git push origin name-of-your-bugfix-or-feature
```

10. Submit a pull request through the GitHub website.
