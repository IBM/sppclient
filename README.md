# sppclient
This repo holds two components.

An SDK that can be used by anyone interested in integrating ECX operations in their workflow.
A command line utility with which ECX operations can be performed.
Installation
For now, directly install into a local virtual env:

# clone the project and change into the directory.
$ git clone https://github.com/sppautomation/sppclient.git
$ cd ecxlib

# Create a virtual environment
$ python3 -m venv $HOME/venv/ecxlib

# Install the library
$ $HOME/venv/ecxlib/bin/pip install -e .

$ export PATH=$PATH:$HOME/venv/ecxlib/bin
At this point, the library can be used.

Usage
$ ecxcli --help

# This connects to ECX on localhost.
$ ecxcli --user admin --passwd <PASSWORD> job list

# To connect to a different host. Default user is "admin".
$ ecxcli --url https://1.2.3.4:8443 --passwd <PASSWORD> job list

$ ecxcli job list

$ ecxcli job run --mon <ID>
Notes
After a successful login, the command "remembers" the login session so there is no need to pass user name and password with every run.
Known Issues
When "https" URL is used, there are some warnings displayed on the console. We need to find a way to get rid of them.
Need to add job session cleanup actions to the JobAPI
