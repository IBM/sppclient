# sppclient
This repo holds two components.

An SDK that can be used by anyone interested in integrating SPP operations in their workflow.
A command line utility with which SPP operations can be performed.
Installation
For now, directly install into a local virtual env:

# Clone the project and change into the directory.
$ git clone https://github.com/sppautomation/sppclient.git
$ cd spplib

# Create a virtual environment
$ python3 -m venv $HOME/venv/spplib

# Install the library
$ $HOME/venv/spplib/bin/pip install -e .

$ export PATH=$PATH:$HOME/venv/spplib/bin
At this point, the library can be used.

Usage
$ sppcli --help

# This connects to SPP on localhost.
$ sppcli --user admin --passwd <PASSWORD> job list

# To connect to a different host. Default user is "admin".
$ sppcli --url https://1.2.3.4:8443 --passwd <PASSWORD> job list

$ sppcli job list

$ sppcli job run --mon <ID>

# Sample commands to run scripts.

$ python3 script.py --h (This command provides a list of input parameters needed to run the script)

$ python3 createsite.py --host="https://x.x.x.x" --user="admin" --pass="password" --sitename="samplesite" --sitedesc="This is a sample site"

$ python3 runjob.py --host="https://x.x.x.x" --user="admin" --pass="password" --jobname="samplejob"


