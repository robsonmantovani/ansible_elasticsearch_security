> ELASTICSEARCH_SECURITY_API-KEY    (plugins/modules/elasticsearch_security_apikey.py)

        This module allows you to manage Elasticsearch security API
        keys. It can create or invalidate API keys.

OPTIONS (= is mandatory):

- api_key_metadata
        Dictionary specifying the metadata for the API key.
        default: null

= api_key_name
        Name of the API key to be managed.

= api_key_role_descriptors
        Dictionary specifying the role descriptors for the API key.

= es_pass
        Elasticsearch password.
        no_log: true

= es_url
        URL of the Elasticsearch cluster.

= es_user
        Elasticsearch username.

= state
        Specifies whether the API key should be present or absent.
        choices: [present, absent]

= user_name
        Name of the user associated with the API key.


NOTES:
      * This module requires the `elasticsearch` Python library
        to be installed.


SEE ALSO:
      * Module elasticsearch_security_user


REQUIREMENTS:  elasticsearch

AUTHOR: Robson Mantovani
