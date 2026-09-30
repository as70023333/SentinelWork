# Logic Apps

Sentinel playbooks: incident trigger -> HTTP POST to the agent webhook (`/api/webhook/sentinel`) with the incident ARM ID. Paired with an automation rule "When incident is created -> Run playbook".

See: [README section 5.7](../../Agents/Autonomous_SOC_Analyst/README.md#57-connect-sentinel-to-the-agent-pick-one)
