"""Wrap rules and workbooks in ARM templates that ``az deployment group create`` accepts."""

from __future__ import annotations

import json

from .rules import API_VERSION, Rule, rule_properties
from .workbooks import Workbook, gallery

TEMPLATE_SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
WORKBOOK_API_VERSION = "2022-04-01"
WORKSPACE_PARAMETER = {
    "type": "String",
    "metadata": {"description": "Name of the Log Analytics workspace that Microsoft Sentinel is enabled on."},
}


def literal(value):
    """Make sure ARM reads every string as text.

    ARM evaluates a string that starts with "[" and ends with "]" as an expression. A query or a
    description could by chance look like that, so such a string gets the documented escape: a
    second "[" at the start.
    """
    if isinstance(value, str):
        return "[" + value if value.startswith("[") and value.endswith("]") else value
    if isinstance(value, list):
        return [literal(item) for item in value]
    if isinstance(value, dict):
        return {key: literal(item) for key, item in value.items()}
    return value


def rules_template(rules: list[Rule], enabled: bool = False) -> dict:
    """An ARM template with one scheduled analytics rule per rule, in the shape Sentinel exports."""
    resources = []
    for rule in rules:
        resources.append(
            {
                "id": "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', "
                f"parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/{rule.guid}')]",
                "name": f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/{rule.guid}')]",
                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                "kind": "Scheduled",
                "apiVersion": API_VERSION,
                "properties": literal(rule_properties(rule, enabled)),
            }
        )
    return {
        "$schema": TEMPLATE_SCHEMA,
        "contentVersion": "1.0.0.0",
        "parameters": {"workspace": WORKSPACE_PARAMETER},
        "resources": resources,
    }


def workbooks_template(books: list[Workbook], rules: list[Rule]) -> dict:
    """An ARM template that saves every workbook to the workspace's resource group."""
    resources = []
    for book in books:
        resources.append(
            {
                "type": "Microsoft.Insights/workbooks",
                "apiVersion": WORKBOOK_API_VERSION,
                # A workbook's resource name must be a GUID. Deriving it from the workspace and the
                # workbook means a second deployment updates the workbook instead of adding a copy.
                "name": f"[guid(variables('workspaceId'), 'sentinelwork-workbook-{book.key}')]",
                "location": "[parameters('location')]",
                "kind": "shared",
                "properties": {
                    "displayName": literal(book.name),
                    "serializedData": literal(json.dumps(gallery(book, rules), separators=(",", ":"), ensure_ascii=False)),
                    "version": "1.0",
                    "sourceId": "[variables('workspaceId')]",
                    "category": "sentinel",
                },
            }
        )
    return {
        "$schema": TEMPLATE_SCHEMA,
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": WORKSPACE_PARAMETER,
            "location": {
                "type": "String",
                "defaultValue": "[resourceGroup().location]",
                "metadata": {"description": "Azure region for the workbooks. Use the region of the workspace."},
            },
        },
        "variables": {"workspaceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"},
        "resources": resources,
    }


def template_text(template: dict) -> str:
    return json.dumps(template, indent=2, ensure_ascii=False) + "\n"
