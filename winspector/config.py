# Centralised configuration for WinSpector.
# All environment-specific values live here.
# Override any value via environment variable, no source edits needed.

import os
import platform
from pathlib import Path

# Elasticsearch
"""
 Endpoint for alert export via the Bulk API.
 Override: set WINSPECTOR_ELASTIC_URL environment variable.

 SECURITY WARNING: WinSpector sends alert data over plain HTTP with no authentication. This is only safe on an isolated, trusted network segment with xpack.security.enabled: false on the Elasticsearch side.
 Do NOT point this at an internet-reachable or shared-network Elasticsearch instance without enabling TLS and API-key authentication first.
"""
ELASTIC_URL: str = os.environ.get(
    "WINSPECTOR_ELASTIC_URL",
    "http://localhost:9200",
)

# Elasticsearch index name for WinSpector alerts.
# Override: set WINSPECTOR_ELASTIC_INDEX environment variable.
ELASTIC_INDEX: str = os.environ.get(
    "WINSPECTOR_ELASTIC_INDEX",
    "winspector-alerts",
)

# Host identity
"""
 Hostname tag written to every exported alert document.
 Defaults to the machine's actual hostname.
 Override: set WINSPECTOR_COMPUTER_NAME environment variable.
"""
COMPUTER_NAME: str = os.environ.get(
    "WINSPECTOR_COMPUTER_NAME",
    platform.node(),
)

# Self-suppression
"""
 Absolute path to the directory WinSpector is installed in (lowercase).
 Computed from this file's location — works regardless of where the repo is cloned. Used in alert_scorer.py to suppress WinSpector's own process activity from being scored as suspicious.
"""
WINSPECTOR_INSTALL_DIR: str = str(
    Path(__file__).resolve().parent.parent
).lower()

# Authentication
"""
 Elasticsearch API key for authenticated exports.
 Override: set WINSPECTOR_ELASTIC_API_KEY environment variable.
 Format: base64-encoded "id:api_key" string from Kibana Stack Management.
 Leave unset (default) when using security-disabled lab Elasticsearch.

 To create an API key in Kibana:
   Stack Management -> API Keys -> Create API key
   Set privileges: index write on winspector-alerts
   Copy the encoded value and set WINSPECTOR_ELASTIC_API_KEY
"""
ELASTIC_API_KEY: str = os.environ.get(
    "WINSPECTOR_ELASTIC_API_KEY",
    "",
)
