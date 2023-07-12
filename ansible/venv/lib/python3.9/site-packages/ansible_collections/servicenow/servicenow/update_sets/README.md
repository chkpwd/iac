# Update Sets for Ansible Integration
This directory provides update sets that may be required to unlock functionality in ServiceNow.

## ansible_enhanced_inventory
This update set installs a scripted REST API into your ServiceNow instance. This is required for the `enhanced` parameter in the `now` inventory plugin to function. "enhanced" provides CI relationship data to the plugin so that it can build additional groups in your inventory.