from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = """
    name: bws_cache
    author:
      - tigattack (@tigattack)
    requirements:
      - requests Python package
      - BWS_ACCESS_TOKEN environment variable
      - BWS_CACHE_URL environment variable
    short_description: Retrieve secret from Bitwarden Secrets Manager Cache
    description:
      - Retrieve a secret from the Bitwarden Secrets Manager Cache using its ID or key.
    options:
      _terms:
        description: Secret ID or key
        example: my_secret_id
        required: true
        type: str
"""

EXAMPLES = """
- name: Retrieve secret by ID
  ansible.builtin.debug:
    msg: >-
      {{ lookup('bws_cache', '01fae166-302b-4e75-b7a4-c6887ef7e3a8') }}

- name: Retrieve secret by key
  ansible.builtin.debug:
    msg: >-
      {{ lookup('bws_cache', 'my_secret_key') }}
"""

RETURN = """
  _raw:
    description: Retrieved secret
    type: str
    returned: success
    sample: "my_secret_value"
"""

import uuid
import os

import requests
from ansible.errors import AnsibleError, AnsibleUndefinedVariable
from ansible.module_utils.common.text.converters import to_text

from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()


class BwsCacheLookup():
    def __init__(self) -> None:
        self.bws_token = os.environ.get('BWS_ACCESS_TOKEN')
        self.bws_cache_url = os.environ.get('BWS_CACHE_URL')
        self.headers = {"Authorization": f"Bearer {self.bws_token}"}

    def is_valid_uuid(self, val):
        """Check if input is a valid UUID"""
        try:
            uuid.UUID(str(val))
            return True
        except ValueError:
            return False

    def query_secret_id(self, secret_id: str):
        """Get and return the secret with the given secret_id."""
        response = requests.get(
            f"{self.bws_cache_url}/id/{secret_id}",
            headers=self.headers,
            timeout=5)
        return response

    def query_secret_key(self, secret_key: str):
        """Get and return the secret with the given secret_key."""
        response = requests.get(
            f"{self.bws_cache_url}/key/{secret_key}",
            headers=self.headers,
            timeout=5)
        return response

    def get_secret(self, secret_identifier: str):
        """Get and return the secret with the given secret_id or secret_key."""
        if not self.bws_token or not self.bws_cache_url:
            raise AnsibleUndefinedVariable("BWS_ACCESS_TOKEN and BWS_CACHE_URL environment variables must be set.")

        if self.is_valid_uuid(secret_identifier):
            display.verbose("bws_cache: input matches UUID format; retrieving by ID.")
            response = self.query_secret_id(secret_identifier)
        else:
            display.verbose("bws_cache: input does not match UUID format; retrieving by key.")
            response = self.query_secret_key(secret_identifier)

        if response.status_code == 200:
            return response.json()
        raise AnsibleError(f"Failed to retrieve secret: {response.status_code} - {response.text}")


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        bws_cache = BwsCacheLookup()

        try:
            return [bws_cache.get_secret(term) for term in terms]
        except Exception as exc:
            raise AnsibleError(f"Error: {to_text(exc)}") from exc
