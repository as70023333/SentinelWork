# SentinelWork

Microsoft Sentinel detection rules, workbooks, cost monitoring, and the Autonomous SOC Analyst agent build-out.

Everything lives under **[Microsoft_Sentinel](Microsoft_Sentinel/)**:

- **[Detection rules](Microsoft_Sentinel/Detection-rules/)**: 28 scheduled analytics rules in seven areas, as readable `.kql` files and deployable templates.
- **[Workbooks](Microsoft_Sentinel/Workbooks/)**: seven SOC workbooks, one per detection area, plus cost and ingestion workbooks.
- **[Autonomous SOC Analyst](Microsoft_Sentinel/Agents/Autonomous_SOC_Analyst/)**: the agent that triages the incidents those rules raise.
