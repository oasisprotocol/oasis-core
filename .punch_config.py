# Punch configuration file.

# For more information, see: https://punch.readthedocs.io/.

__config_version__ = 1

GLOBALS = {
    'serializer': '{{year}}.{{minor}}.{{micro}}',
}

# NOTE: The FILES list is not allowed to be empty, so we need to pass it at
# least a single valid file.
FILES = ["README.md"]

VERSION = [
    {
        'name': 'year',
        'type': 'date',
        'fmt': 'YY',
    },
    {
        'name': 'minor',
        'type': 'integer',
    },
    {
        'name': 'micro',
        'type': 'integer',
    },
]

ACTIONS = {
    'custom_bump': {
        'type': 'conditional_reset',
        'field': 'minor',
        'update_fields': ['year']
    }
}
