
import json
import logging
import sys
import time

import click
from tabulate import tabulate

from spplib.cli import util
from spplib.sdk.client import LogAPI

@click.group()
@util.pass_context
def cli(ctx, **kwargs):
    """Logs resource.
    """

    pass

@cli.command()
@click.option('--ofile', type=click.STRING, help='Output file name for logs archive.')
@util.pass_context
def download(ctx, **kwargs):
    logapi = LogAPI(spp_session=ctx.spp_session)
    outfile = logapi.download_logs(kwargs['ofile'])
    click.echo("Log archive: %s" % outfile)
