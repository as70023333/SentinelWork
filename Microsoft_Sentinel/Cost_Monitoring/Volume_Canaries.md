Volume canaries (TB growth before cost follows)

Canary 2: TB/day by top tables
What it catches: “Did we just ingest a log?” moments
Grounding
Recent Cost Spikes – Azure Subscriptions cdir-sentinel.nonprod and lll.cdir-sentinel.nonprod). 
Sentinel is confirmed as the dominant Azure cost driver.

Canary definition
Daily report:
Top 10 tables by GB ingested
Week‑over‑week delta per table

Canary fires when:
A new table appears in top‑N
A table jumps >X% WoW


Why it’s a canary
Costs lag volume. This catches growth before Finance emails do.
