#!/usr/bin/env python3

from ansible.module_utils.basic import AnsibleModule
from elasticsearch import Elasticsearch, NotFoundError
import warnings

DOCUMENTATION = '''
---
module: elasticsearch_security_role
short_description: Manage Elasticsearch security roles
description:
    - This module allows you to manage Elasticsearch security roles.
    - It can create or delete roles, and update existing roles if necessary.

author: Your Name

options:
  state:
    description:
      - Specifies whether the role should be present or absent.
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

  role_name:
    description:
      - Name of the role to be managed.
    required: true

  role_body:
    description:
      - The body of the role. This should be a dictionary representing the role configuration.
    required: true

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
        role_name=dict(type='str', required=True),
        role_body=dict(type='dict', required=True)
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    state = module.params['state']
    es_url = module.params['es_url']
    es_user = module.params['es_user']
    es_pass = module.params['es_pass']
    role_name = module.params['role_name']
    role_body = module.params['role_body']

    es = Elasticsearch([es_url], basic_auth=(es_user, es_pass))

    try:
        if state == 'present':
            try:
                existing_role = es.security.get_role(name=role_name)[role_name]
                same_cluster = existing_role.get('cluster', []) == role_body.get('cluster', [])
                same_indices = False
                if 'indices' in existing_role and 'indices' in role_body:
                    same_indices_names = existing_role['indices'][0].get('names', []) == role_body['indices'][0].get('names', [])
                    same_indices_privileges = existing_role['indices'][0].get('privileges', []) == role_body['indices'][0].get('privileges', [])
                    same_indices = same_indices_names and same_indices_privileges
                if same_cluster and same_indices:
                    module.exit_json(changed=False, msg=f'Role {role_name} already exists and is identical.')
                else:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", category=DeprecationWarning)
                        es.security.put_role(name=role_name, body=role_body)
                    module.exit_json(changed=True, msg=f'Role {role_name} already exists but is different. Updated successfully.')
            except NotFoundError:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=DeprecationWarning)
                    es.security.put_role(name=role_name, body=role_body)
                module.exit_json(changed=True, msg=f'Role {role_name} created successfully.')

        elif state == 'absent':
            try:
                es.security.delete_role(name=role_name)
                module.exit_json(changed=True, msg=f'Role {role_name} deleted successfully.')
            except NotFoundError:
                module.exit_json(changed=False, msg=f'Role {role_name} does not exist. No action taken.')

    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
