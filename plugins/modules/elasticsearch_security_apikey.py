#!/usr/bin/env python3

from ansible.module_utils.basic import AnsibleModule
from elasticsearch import Elasticsearch, NotFoundError

DOCUMENTATION = '''
---
module: elasticsearch_security_apikey
short_description: Manage Elasticsearch security API keys
description:
    - This module allows you to manage Elasticsearch security API keys.
    - It can create or invalidate API keys.

author: Your Name

options:
  state:
    description:
      - Specifies whether the API key should be present or absent.
    choices: ['present', 'absent']
    required: true

  es_url:
    description:
      - URL of the Elasticsearch cluster.
    required: true

  es_user:
    description:
      - Elasticsearch username.
    required: true

  es_pass:
    description:
      - Elasticsearch password.
    required: true
    no_log: true

  user_name:
    description:
      - Name of the user associated with the API key.
    required: true

  api_key_name:
    description:
      - Name of the API key to be managed.
    required: true

  api_key_role_descriptors:
    description:
      - Dictionary specifying the role descriptors for the API key.
    required: true

  api_key_metadata:
    description:
      - Dictionary specifying the metadata for the API key.
    required: false
  
  tls_verify:
    description:
      - Whether to verify TLS certificates.
    required: false
    type: bool

notes:
  - This module requires the `elasticsearch` Python library to be installed.

requirements:
  - elasticsearch

seealso:
  - module: elasticsearch_security_user
'''


def main():

    module_args = dict(
        state=dict(type='str', choices=['present', 'absent'], required=True),
        es_url=dict(type='str', required=True),
        es_user=dict(type='str', required=True),
        es_pass=dict(type='str', required=True, no_log=True),
        user_name=dict(type='str', required=True),
        api_key_name=dict(type='str', required=True),
        api_key_role_descriptors=dict(type='dict', required=True),
        api_key_metadata=dict(type='dict'),
        tls_verify=dict(type=bool),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    state = module.params['state']
    es_url = module.params['es_url']
    es_user = module.params['es_user']
    es_pass = module.params['es_pass']
    user_name = module.params['user_name']
    api_key_name = module.params['api_key_name']
    api_key_role_descriptors = module.params['api_key_role_descriptors']
    api_key_metadata = module.params['api_key_metadata']
    tls_verify = module.params["tls_verify"]

    if tls_verify == False:
      es = Elasticsearch([es_url], basic_auth=(es_user, es_pass),  verify_certs=False)
    else:
      es = Elasticsearch([es_url], basic_auth=(es_user, es_pass))


    try:
        if state == 'present':
            existing_api_keys = es.security.get_api_key(name=api_key_name)['api_keys']
            if existing_api_keys:
                for api_key in existing_api_keys:
                    if not api_key.get('invalidated'):
                        module.exit_json(changed=False, msg=f'API key "{api_key_name}" already exists and is valid. No action taken.')
                else:
                    es.security.invalidate_api_key(ids=existing_api_keys[0]['id'])
                    api_key = es.security.create_api_key(name=api_key_name, role_descriptors=api_key_role_descriptors, metadata=api_key_metadata)
                    module.exit_json(changed=True, msg=f'API key "{api_key_name}" created successfully:\n{api_key}')

            else:
                api_key = es.security.create_api_key(name=api_key_name, role_descriptors=api_key_role_descriptors, metadata=api_key_metadata)
                module.exit_json(changed=True, msg=f'API key "{api_key_name}" created successfully:\n{api_key}')

        elif state == 'absent':
            existing_api_keys = es.security.get_api_key(name=api_key_name)['api_keys']
            if existing_api_keys:
                for api_key in existing_api_keys:
                    if not api_key.get('invalidated'):
                        es.security.invalidate_api_key(ids=api_key["id"])
                        module.exit_json(changed=True, msg=f'API key "{api_key_name}" invalidated successfully.')
                else:
                    module.exit_json(changed=False, msg=f'API key "{api_key_name}" does not exist. No action taken.')

            else:
                module.exit_json(changed=False, msg=f'API key "{api_key_name}" does not exist. No action taken.')

    except NotFoundError:
        module.exit_json(changed=False, msg=f'User "{user_name}" does not exist. No action taken.')


if __name__ == '__main__':
    main()
