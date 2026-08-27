# Expected scanner outcomes

| Outcome | Exit | State and output |
| --- | --- | --- |
| Complete, no new observation | `0` | Cursor and `last_seen` are updated; event list is empty. |
| New or reviewed finding reappears | `1` | Local event output is prepared, state update succeeds, then `NEW` or `REOPENED` becomes deliverable. |
| Input, provider, pagination, Gist truncation, or state error | `2` | `SCAN_ERROR`; the run is never reported as clean. |

The Actions Summary contains sanitized links and separately labels browser GET
queries as generated but not executed. It never contains matched snippets,
credentials, raw provider responses, or domains in finding records.

An adapter consumes `new-findings.json` only after final exit `1`. Files left by
exit `2` are not deliverable notification evidence.
