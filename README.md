# Elasticsearch Security

The "Elasticsearch Security" collection provides Ansible modules to manage Elasticsearch security. These modules allow you to create, update, and delete users, roles, and security API keys in Elasticsearch. With this collection, you can automate permission management and access control in your Elasticsearch cluster, enhancing the security of your infrastructure.

## Modules

### elasticsearch_security_api-key

This module allows you to manage Elasticsearch security API keys. It can create or invalidate API keys.

#### Options:

- `api_key_metadata` (required): Dictionary specifying the metadata for the API key.
- `api_key_name` (required): Name of the API key to be managed.
- `api_key_role_descriptors` (required): Dictionary specifying the role descriptors for the API key.
- `es_pass` (required): Elasticsearch password.
- `es_url` (required): URL of the Elasticsearch cluster.
- `es_user` (required): Elasticsearch username.
- `state` (required): Specifies whether the API key should be present or absent.
- `user_name`: Name of the user associated with the API key.

> This module requires the `elasticsearch` Python library to be installed.

### elasticsearch_security_role

This module allows you to manage Elasticsearch security roles. It can create, delete, and update existing roles if necessary.

#### Options:

- `es_pass` (required): Elasticsearch password.
- `es_url` (required): URL of the Elasticsearch cluster.
- `es_user` (required): Elasticsearch username.
- `role_body` (required): The body of the role. This should be a dictionary representing the role configuration.
- `role_name` (required): Name of the role to be managed.
- `state` (required): Specifies whether the role should be present or absent.

> This module requires the `elasticsearch` Python library to be installed.

### elasticsearch_security_user

This module allows you to manage Elasticsearch security users. It can create, update, or delete users.

#### Options:

- `es_pass` (required): Elasticsearch password.
- `es_url` (required): URL of the Elasticsearch cluster.
- `es_user` (required): Elasticsearch username.
- `force`: Forcefully update the user even if it already exists.
- `state` (required): Specifies whether the user should be present or absent.
- `user_email`: Email address of the user.
- `user_full_name`: Full name of the user.
- `user_name` (required): Name of the user to be managed.
- `user_password`: Password for the user.
- `user_roles`: List of roles assigned to the user.

> This module requires the `elasticsearch` Python library to be installed.

## Requirements

- `elasticsearch`: Python library for interacting with Elasticsearch.

## Author

- Name: Robson Mantovani
- Contact: robsonmantovani@gmail.com

