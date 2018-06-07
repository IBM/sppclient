
import json

import click
from tabulate import tabulate

from spplib.cli import util

@click.group()
@util.pass_context
def cli(ctx, **kwargs):
    """VM resource.
    """

    pass

def get_sla_info(spp_session):
    sla_policies = spp_session.get(restype='sla')['slapolicies']

    return dict([(int(x['id']), x['name']) for x in sla_policies]) 

@cli.command()
@util.pass_context
@click.argument('pattern')
def search(ctx, pattern):
    if not pattern:
        raise Exception('VM pattern is required. ')

    qparams = {'resourceType': 'vm', 'from': 'hlo', 'pageSize': '500'}
    data = {'name': pattern, 'hypervisorType': 'vmware'}

    sla_info = get_sla_info(ctx.spp_session)

    resp = ctx.spp_session.post(restype='hypervisor', path='search', data=data, params=qparams)

    table_info = []
    for vm in resp['vms']:
        sla_ids = set([x['storageProfileId'] for x in vm['copies']])
        slas = set([sla_info[sla_id] for sla_id in sla_ids])
        table_info.append((vm['name'], slas))

    if not table_info:
        return

    print
    click.echo_via_pager(tabulate(table_info, headers=["Name", "SLAs"]))
    print


