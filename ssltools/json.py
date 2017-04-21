import sys
from datetime import datetime
import json

# helper callback function to serial datatypes that are not natively
# convertible to JSON.
def serializer_cb(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj.__str__()

def to_json(obj, pretty = False):
    """Convert object to JSON.
    This method extends json.dumps by supporting additional datatypes (currently
    only datetime objects). It supports the optional "pretty" argument (defaults
    to false). If pretty is true, an indent of 2 is used.
    """
    json = sys.modules["json"]
    if pretty:
        return json.dumps(obj, indent = 2, sort_keys = True, default = serializer_cb)
    else:
        return json.dumps(obj, sort_keys = True, default = serializer_cb)
