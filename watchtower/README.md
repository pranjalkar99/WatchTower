# Drop WatchTower onto any agent in 3 lines:

```python
from watchtower import SentinelClient

sentinel = SentinelClient("http://localhost:8000")
result = await sentinel.protect("travel", user_message, run=lambda: graph.invoke(...))
```

See `examples/travel-agent/` for a full LangGraph demo.
