"""Build and check the Microsoft Sentinel detection rules and workbooks in this repository.

The readable sources (one ``.kql`` file per rule, one ``.toml`` file per workbook) are turned
into the files Sentinel accepts: ARM templates for the rules, gallery JSON and an ARM template
for the workbooks. Standard library only; Python 3.11 or newer.
"""

__version__ = "1.0.0"
