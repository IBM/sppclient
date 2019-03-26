import logging
import os
import subprocess
import sys
import threading
import time
import traceback
import re

logger = logging.getLogger(__name__)


def read_file(filename, ignore_error=False):
    output = []
    try:
        fh = open(filename, "r")
        for line in fh:
            output.append(line.strip())
        fh.close()
    except:
        logger.error(traceback.format_exc())
        if not ignore_error:
            raise
    return output


def write_file(filename, contents, mode="w", ignore_error=False):
    try:
        fh = open(filename, mode)
        for line in contents:
            fh.write(line)
            fh.write("\n")
        fh.close()
    except:
        logger.error(traceback.format_exc())
        if not ignore_error:
            raise


def remove_file(filename, recursive=False):
    if recursive:
        run_shell_command("rm -rf \"%s\"" % filename, use_sudo=True, ignore_error=True)
    else:
        run_shell_command("rm -f \"%s\"" % filename, use_sudo=True, ignore_error=True)


def get_pid_children(pid, recursive=False):
    pidlist = run_shell_command("ps --ppid %s -o pid=" % pid, ignore_error=True, log_error_as=None)[1]
    if not recursive:
        return pidlist
    temp_list = [p for p in pidlist]
    for p in temp_list:
        pidlist.extend(get_pid_children(p, recursive=recursive))
    return pidlist


def kill_pid(pid, signal="15", children=False, recursive=False):
    pidlist = [str(pid)]
    if children:
        pidlist.extend(get_pid_children(pid, recursive=recursive))
    run_shell_command("kill -s %s %s" % (signal, " ".join(pidlist).strip()), use_sudo=True, log_cmd_as=logging.INFO)


def run_background_command(command, use_sudo=False, sudo_user="root", sudo_login=False, log_cmd_as=logging.DEBUG):
    logger.log(log_cmd_as, "Executing background command: %s" % command)
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class CommandFailureError(Exception):
    def __init__(self, cmd):
        msg = "Command failed: %s" % cmd
        super().__init__(msg)


class CommandTimeoutError(Exception):
    def __init__(self, cmd):
        msg = "Command timed out: %s" % cmd
        super().__init__(msg)


def run_shell_command(command, cmd_input=None, use_sudo=False, sudo_user="root", sudo_login=False, timeout=480,
                      ignore_error=False, log_error_as=logging.WARN, log_cmd_as=logging.DEBUG, output_to_file=False,
                      mask_text=[], use_stdout=False, pidfile=None):
    outfile_name = "/tmp/bdg-%s-%s-out.txt" % (os.getpid(), int(time.time()))
    outfile = open(outfile_name, "w")
    if cmd_input is not None:
        infile_name = "/tmp/bdg-%s-%s-in.txt" % (os.getpid(), int(time.time()))
        infile = open(infile_name, "w")
        for line in cmd_input:
            infile.write(line + "\n")
        infile.close()
        infile = open(infile_name, "r")
    else:
        infile_name = None
        infile = None

    log_command = command
    for text in mask_text:
        log_command = re.sub(text, "xxxx", log_command)
    log_command_full = log_command

    if use_sudo:
        sudo_prefix = "sudo -n"  # General prefix: no password prompt
        if sudo_user != "root":
            sudo_prefix = sudo_prefix + " -u '%s'" % sudo_user  # Add "-u username"
        if sudo_login:
            sudo_prefix = sudo_prefix + " -i"  # Add -i to create login shell
        command = sudo_prefix + " " + command
        log_command_full = sudo_prefix + " " + log_command

    logger.log(log_cmd_as, "Executing command: " + log_command_full)

    if use_stdout:
        stdout = sys.stdout
    else:
        stdout = outfile

    proc = subprocess.Popen(command, stdin=infile, stdout=stdout, stderr=subprocess.STDOUT, shell=True)
    if pidfile is not None:
        with open(pidfile, "w") as f:
            f.write("{}".format(proc.pid))

    thread_proc = threading.Thread(target=proc.communicate)
    thread_proc.start()
    thread_proc.join(timeout)

    if thread_proc.is_alive():
        logger.error("Timed out (%d seconds) waiting for command to complete: %s" % (timeout, log_command_full))
        try:
            kill_pid(proc.pid, children=True, recursive=True)
        except:
            logger.warning(traceback.format_exc())
            logger.warning("Failed to kill process %d and/or its children" % proc.pid)
        outfile.close()
        if infile:
            infile.close()
            os.remove(infile_name)
            cmd_result = read_file(outfile_name, ignore_error=True)
            os.remove(outfile_name)
            logger.info("Output of timed out command: %s" % cmd_result)
        raise CommandTimeoutError(log_command)

    outfile.close()
    if infile:
        infile.close()
        os.remove(infile_name)

    if output_to_file:
        # caller will be responsible for reading and deleting this file
        cmd_result = outfile_name
    else:
        cmd_result = read_file(outfile_name, ignore_error=True);
        os.remove(outfile_name);

    if proc.returncode != 0:
        if log_error_as is not None:
            logger.log(log_error_as, "Return code %d: %s" % (proc.returncode, log_command_full))
            if (not output_to_file) and (len(cmd_result) > 0):
                logger.log(log_error_as, "Ouput: %s" % str(cmd_result))
        if not ignore_error:
            if len(cmd_result) > 0 and len(cmd_result) < 4:
                raise CommandFailureError("; ".join(cmd_result))
            else:
                raise CommandFailureError(log_command)

    return proc.returncode, cmd_result
