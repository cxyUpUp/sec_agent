import datetime
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
}