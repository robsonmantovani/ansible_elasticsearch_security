> ELASTICSEARCH_SECURITY_ROLE    (plugins/modules/elasticsearch_security_role.py)

        This module allows you to manage Elasticsearch security roles.
        It can create or delete roles, and update existing roles if
        necessary.

OPTIONS (= is mandatory):

= es_pass
        Elasticsearch password.
        no_log: true

= es_url
        URL of the Elasticsearch cluster.

= es_user
        Elasticsearch username.

= role_body
        The body of the role. This should be a dictionary representing
        the role configuration.

= role_name
        Name of the role to be managed.

= state
        Specifies whether the role should be present or absent.
        choices: [present, absent]


NOTES:
      * This module requires the `elasticsearch` Python library
        to be installed.


SEE ALSO:
      * Module elasticsearch_security_user


REQUIREMENTS:  elasticsearch

AUTHOR: Robson Mantovani
