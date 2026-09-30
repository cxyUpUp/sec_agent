import datetime

from agent.coding_tools import (
    glob_files,
    list_dir,
    read_file,
    run_command,
    search_text,
    str_replace,
    write_file,
)
from agent.pwned import pwned_check


def get_time():
    return str(datetime.datetime.now())


def echo(response=""):
    return response


def pwned_check_tool(password: str):
    return pwned_check(password)


TOOL_MAP = {
    "get_time": get_time,
    "echo": echo,
    "pwned_check": pwned_check_tool,
    "list_dir": list_dir,
    "read_file": read_file,
    "write_file": write_file,
    "str_replace": str_replace,
    "search_text": search_text,
    "glob_files": glob_files,
    "run_command": run_command,
}
