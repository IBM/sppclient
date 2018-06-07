
import json

import click
from tabulate import tabulate

from spplib.cli import util

RESTYPE = 'sla'

@click.group()
@util.pass_context
def cli(ctx, **kwargs):
    """SLA resource.
    """

    pass

@cli.command()
@util.pass_context
def list(ctx, **kwargs):
    print()

    resp = ctx.spp_session.get(restype=RESTYPE)
    sla_policies = resp['slapolicies']

    if ctx.json:
        ctx.print_response(sla_policies)
        return

    table_info = [(x['name'], x['id']) for x in sla_policies]
    if not table_info:
        return

    print
    click.echo_via_pager(tabulate(table_info, headers=["Name", "ID"]))
    print

# I see the following in "trigger" element but SLA creation is working
#   "activateDate": 1519362000000
# even without this.

sla_req_template = """
{{
    "version": "1.0",
    "spec": {{
        "simple": true,
        "subpolicy": [
            {{
                "type": "REPLICATION",
                "trigger": {{
                    "frequency": 100,
                    "type": "DAILY"
                }},
                "software": true,
                "retention": {{
                    "age": 15
                }},
                "site": "Primary"
            }}
        ]
    }},
    "name": "{name}"
}}
"""

@cli.command()
@util.pass_context
@click.argument('name')
def create(ctx, name):
    reqdata_str = sla_req_template.format(name=name)
    resp = ctx.spp_session.post(restype=RESTYPE, data=json.loads(reqdata_str))

@cli.command()
@util.pass_context
@click.argument('name')
def delete(ctx, name):
    ctx.spp_session.delete(restype=RESTYPE, resid=name)


