import subprocess

def execute_user_script(script_cmd: str):
    # Planted vulnerability: subprocess with shell=True
    return subprocess.Popen(script_cmd, shell=True)
