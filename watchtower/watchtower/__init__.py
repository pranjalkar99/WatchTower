"""WatchTower Sentinel — attach security monitoring to any AI agent."""

from watchtower.client import GuardResult, SentinelClient
from watchtower.decorators import sentinel_guard

__all__ = ["SentinelClient", "GuardResult", "sentinel_guard"]
__version__ = "0.1.0"
