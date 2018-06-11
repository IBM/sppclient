
import click
from tabulate import tabulate

from sppclient.cli import util

from spplib.sdk.client import SppAPI
from spplib.sdk.client import AssociationAPI
from spplib.sdk.client import resource_to_listfield

@click.group()
@click.option('--type', help='Resource type.')
@click.option('--endpoint', help='Top level end point, not including "api". E.g. "endeavour/policy"')
@util.pass_context
def cli(ctx, type, endpoint, **kwargs):
    """generic resource.
    """

    ctx.restype = type
    ctx.endpoint = endpoint

@cli.command()
@click.option('--fields', help='Fields to print as comma separated values.')
@click.option('--listfield', help='Name of the field containing list of resources.')
@util.pass_context
def list(ctx, **kwargs):
    resp = ctx.spp_session.get(restype=ctx.restype, endpoint=ctx.endpoint)

    list_field = kwargs.get('listfield') or resource_to_listfield.get(ctx.restype) or (ctx.restype + 's')

    if ctx.json or list_field not in resp:
        ctx.print_response(resp)
        return

    resources = resp[list_field]
    if kwargs['fields']:
        fields = [x.strip() for x in kwargs['fields'].split(',')]
    else:
        fields = ["name", "id"]

    table_data = []
    for res in resources:
        row = []
        for field in fields:
            row.append(res.get(field, None))

        table_data.append(row)

    if not table_data:
        return

    print
    click.echo_via_pager(tabulate(table_data, headers=fields))
    print

@cli.command()
@click.argument('id', type=click.INT)
@util.pass_context
def info(ctx, id, **kwargs):
    resp = ctx.spp_session.get(restype=ctx.restype, resid=id, endpoint=ctx.endpoint)
    ctx.print_response(resp)

@cli.command()
@click.argument('id', type=click.INT)
@util.pass_context
def usedby(ctx, id, **kwargs):
    resp = AssociationAPI(spp_session=ctx.spp_session).get_using_resources(ctx.restype, id)["resources"]
    if ctx.json:
        ctx.print_response(resp)
        return

    table_data = [(x["type"], x["resourceId"], x["name"]) for x in resp]

    print
    click.echo_via_pager(tabulate(table_data, headers=["Type", "ID", "Name"]))
    print

@cli.command()
@click.argument('id', type=click.INT)
@util.pass_context
def delete(ctx, id, **kwargs):
    resp = ctx.spp_session.delete(restype=ctx.restype, resid=id, endpoint=ctx.endpoint)
    if resp:
        ctx.print_response(resp)
