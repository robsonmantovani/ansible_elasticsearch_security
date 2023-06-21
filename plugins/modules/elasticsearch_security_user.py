#!/usr/bin/env python3

from ansible.module_utils.basic import AnsibleModule
from elasticsearch import Elasticsearch, NotFoundError

DOCUMENTATION = """
---
module: elasticsearch_security_user
short_description: Manage Elasticsearch security users
description:
    - This module allows you to manage Elasticsearch security users.
    - It can create, update, or delete users.

author: Your Name

options:
  state:
    description:
      - Specifies whether the user should be present or absent.
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
      - Name of the user to be managed.
    required: true

  user_full_name:
    description:
      - Full name of the user.
    required: false

  user_email:
    description:
      - Email address of the user.
    required: false

  user_password:
    description:
      - Password for the user.
    required: false
    no_log: true

  user_roles:
    description:
      - List of roles assigned to the user.
    required: false

  force:
    description:
      - Forcefully update the user even if it already exists.
    required: false
    type: bool

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
  - module: elasticsearch_security_role
"""


def main():
    module_args = dict(
        state=dict(type="str", choices=["present", "absent"], required=True),
        es_url=dict(type="str", required=True),
        es_user=dict(type="str", required=True),
        es_pass=dict(type="str", required=True, no_log=True),
        user_name=dict(type="str", required=True),
        user_full_name=dict(type="str"),
        user_email=dict(type="str"),
        user_password=dict(type="str", no_log=True),
        user_roles=dict(type="list", elements="str"),
        force=dict(type=bool),
        tls_verify=dict(type=bool),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    state = module.params["state"]
    es_url = module.params["es_url"]
    es_user = module.params["es_user"]
    es_pass = module.params["es_pass"]
    user_name = module.params["user_name"]
    user_full_name = module.params["user_full_name"]
    user_email = module.params["user_email"]
    user_password = module.params["user_password"]
    user_roles = module.params["user_roles"]
    force = module.params["force"]
    tls_verify = module.params["tls_verify"]

    if tls_verify == False:
      es = Elasticsearch([es_url], basic_auth=(es_user, es_pass),  verify_certs=False)
    else:
      es = Elasticsearch([es_url], basic_auth=(es_user, es_pass))

    try:
        existing_user = es.security.get_user(username=user_name)

        if state == "present" and force:
            if user_name in existing_user:
                es.security.delete_user(username=user_name)
                es.security.put_user(
                    username=user_name,
                    password=user_password,
                    roles=user_roles,
                    full_name=user_full_name,
                    email=user_email,
                    refresh="true",
                )
            else:
                raise NotFoundError

        elif state == "present":
            if user_name in existing_user:
                module.exit_json(
                    changed=False,
                    msg=f"User {user_name} already exists. No state taken.",
                )
            else:
                raise NotFoundError

        elif state == "absent":
            if user_name not in existing_user:
                module.exit_json(
                    changed=False,
                    msg=f"User {user_name} does not exist. No state taken.",
                )

        if not module.check_mode:
            if state == "absent":
                es.security.delete_user(username=user_name)

        module.exit_json(changed=True, msg=f"User {user_name} {state}d successfully.")

    except NotFoundError:
        if state == "present":
            es.security.put_user(
                username=user_name,
                password=user_password,
                roles=user_roles,
                full_name=user_full_name,
                email=user_email,
                refresh="true",
            )
            module.exit_json(
                changed=True, msg=f"User {user_name} presentd successfully."
            )
        elif state == "absent":
            module.exit_json(
                changed=False, msg=f"User {user_name} does not exist. No state taken."
            )


if __name__ == "__main__":
    main()
