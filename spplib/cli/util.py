
import json

import click

def remove_links(obj):
    if type(obj) is dict:
        if obj.has_key("links"):
            del obj["links"]

        for k, v in obj.iteritems():
            remove_links(v)

        return

    if type(obj) is list:
        for item in obj:
            remove_links(item)

        return

    return

class Context(object):
    def __init__(self):
        self.links = False
        self.json = False

    def print_response(self, resp):
        if not self.links:
            remove_links(resp)

        click.echo_via_pager(json.dumps(resp, indent=4))

pass_context = click.make_pass_decorator(Context, ensure=True)

