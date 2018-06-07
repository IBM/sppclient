
import json
import logging
import sys
import time

import click
from tabulate import tabulate

from spplib.cli import util
from spplib.sdk.client import JobAPI

def print_job_log(log_entries):
    for entry in log_entries:
        logtype = entry['type']
        line = '%s %s\n' % (time.ctime(entry['logTime']/1000).strip(), entry['message'])

        if logtype == 'ERROR':
            click.secho(line, fg='red')
        elif logtype == 'WARN':
            click.secho(line, fg='magenta')
        else:
            click.echo(line)

def monitor(jobapi, job, interval_sec=10):
    status = job['status']
    logging.info("job status: %s" % status)
    
    active = False
    counter = 0

    try:
        jobsession_id = int(job['curr_jobsession_id'])
    except KeyError:
        raise Exception("Unable to find job session ID...")

    log_entries_index = 0
    while True:
        if active and (status == "PENDING"):
            # Job moved from active state(s) to PENDING so
            # it should be treated as done.
            break

        if status == "IDLE":
            break

        if (not active) and (status != "PENDING"):
            # Job moved from PENDING to other active states.
            active = True

        log_entries = jobapi.get_log_entries(jobsession_id, page_start_index=log_entries_index)
        log_entries_index += len(log_entries)
        print_job_log(log_entries)

        time.sleep(interval_sec)
        counter = counter + 1

        status = jobapi.status(job['id'])['currentStatus']
        logging.info("job status: %s" % status)

    logging.info("Job is done, getting last batch of log entries...")
    print_job_log(jobapi.get_log_entries(jobsession_id, page_start_index=log_entries_index))

    return status

    # Job is done so it is now guaranteed to have "lastrun" field.
    # jobStatus = JobsessionAPI.monitor(JobAPI.get(job.id).lastrun.sessionId).status
    # println "jobStatus 3 (${job.id}): ${jobStatus}"
    # return jobStatus

@click.group()
@util.pass_context
def cli(ctx, **kwargs):
    """Job resource.
    """

    pass

def format_last_run_time(run_time):
    if not run_time: return None

    return time.ctime(int(run_time)/1000)

@cli.command()
@util.pass_context
def list(ctx, **kwargs):
    jobs = JobAPI(spp_session=ctx.spp_session).list()
    if ctx.json:
        ctx.print_response(jobs)
        return

    job_table_info = [(x['name'], x['id'], x['status'], format_last_run_time(x['lastRunTime'])) for x in jobs]
    if not job_table_info:
        return

    print
    click.echo_via_pager(tabulate(job_table_info, headers=["Name","ID", "Status", "Last run"]))
    print

@cli.command()
@click.argument('jobid', type=click.INT)
@util.pass_context
def delete(ctx, jobid, **kwargs):
    resp = JobAPI(spp_session=ctx.spp_session).delete(jobid)
    if resp:
        ctx.print_response(resp)

@cli.command()
@click.argument('jobid', type=click.INT)
@util.pass_context
def info(ctx, jobid, **kwargs):
    resp = JobAPI(spp_session=ctx.spp_session).get(jobid)
    ctx.print_response(resp)

@cli.command()
@click.option('-i', type=click.INT, metavar='interval_sec', default=10, help='Interval, in seconds, for polling.')
@click.option('--mon', is_flag=True, help='Enables job monitoring.')
@click.argument('jobid', type=click.INT)
@util.pass_context
def run(ctx, jobid, **kwargs):
    jobapi = JobAPI(spp_session=ctx.spp_session)
    job = jobapi.run(jobid)
    if kwargs['mon']:
        monitor(jobapi, job, kwargs['i'])
    else:
        ctx.print_response(job)
