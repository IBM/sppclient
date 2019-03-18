
import json
import logging
import sys
import time
import re

import click
from tabulate import tabulate

from spplib.cli import util
from spplib.sdk.client import LogAPI, SppAPI, DiagAPI, JobAPI, JobSessionAPI


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

@cli.command()
@click.option('--ofile', type=click.STRING, help='Output file name for logs archive.')
@click.option('--jobsessionid', help='Session Id to download logs.')
@util.pass_context
def download_job(ctx, ofile, jobsessionid):

    diagapi = DiagAPI(spp_session=ctx.spp_session)
    jobsessapi = JobSessionAPI(spp_session=ctx.spp_session)
    diag_href = None

    jobsession = jobsessapi.get_jobsession(jobsessionid)
    diag_href = jobsession['links']['diagnostics']['href']

    outfile = diagapi.get_joblogs(url=diag_href, outfile=ofile)
    click.echo("Log archive: %s" % outfile)



