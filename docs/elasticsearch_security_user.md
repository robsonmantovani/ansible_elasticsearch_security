> ELASTICSEARCH_SECURITY_USER    (plugins/modules/elasticsearch_security_user.py)

        This module allows you to manage Elasticsearch security users.
        It can create, update, or delete users.

OPTIONS (= is mandatory):

= es_pass
        Elasticsearch password.
        no_log: true

= es_url
        URL of the Elasticsearch cluster.

= es_user
        Elasticsearch username.

- force
        Forcefully update the user even if it already exists.
        default: null
        type: bool

= state
        Specifies whether the user should be present or absent.
        choices: [present, absent]

- user_email
        Email address of the user.
        default: null

- user_full_name
        Full name of the user.
        default: null

= user_name
        Name of the user to be managed.

- user_password
        Password for the user.
        default: null
        no_log: true

- user_roles
        List of roles assigned to the user.
        default: null


NOTES:
      * This module requires the `elasticsearch` Python library
        to be installed.


SEE ALSO:
      * Module elasticsearch_security_role


REQUIREMENTS:  elasticsearch

AUTHOR: Robson Mantovani
