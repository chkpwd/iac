Because of an issue in Ansible, Hub Automation cannot use doc fragments from an external collection as:
```
    - azure.azcollection.azure
    - azure.azcollection.azure_tags
```

Red Hat asked us to make local copies of the azcollection doc fragments.  They are in
```
ansible_collections/netapp/azure/plugins/doc_fragments/azure.py
ansible_collections/netapp/azure/plugins/doc_fragments/azure_tags.py
```

Once the Ansible issue is fixed, we should remove these copies, as they may be out of sync with the azcollection.
