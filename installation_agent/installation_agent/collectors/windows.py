import json
import subprocess
import winreg


def get_run_keys() -> list[dict]:
    """Collect Windows Run-key persistence entries (T1547.001)."""
    entries = []

    locations = [
        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM",
        ),
    ]

    for hive, registry_path, hive_name in locations:
        try:
            with winreg.OpenKey(hive, registry_path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        entries.append({
                            "name": name,
                            "path": str(value),
                            "location": hive_name,
                            "registry_path": registry_path,
                        })
                        index += 1
                    except OSError:
                        break
        except (FileNotFoundError, PermissionError):
            continue

    return entries


def get_scheduled_tasks() -> list[dict]:
    """Collect scheduled tasks (T1053.005)."""
    entries = []

    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return entries

        current = {}

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()

            if not line:
                if current:
                    entries.append(current)
                    current = {}
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key == "TaskName":
                current["name"] = value
            elif key == "Task To Run":
                current["command"] = value
            elif key == "Run As User":
                current["user"] = value
            elif key == "Scheduled Task State":
                current["state"] = value

        if current:
            entries.append(current)

    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError):
        pass

    return entries


def get_services() -> list[dict]:
    """Collect Windows services and executable paths (T1543.003)."""
    entries = []

    powershell = (
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,PathName | "
        "ConvertTo-Json -Compress"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", powershell],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0 or not result.stdout.strip():
            return entries

        data = json.loads(result.stdout)

        if isinstance(data, dict):
            data = [data]

        for service in data:
            entries.append({
                "name": service.get("Name"),
                "display_name": service.get("DisplayName"),
                "state": service.get("State"),
                "start_mode": service.get("StartMode"),
                "path": service.get("PathName"),
            })

    except (
        subprocess.SubprocessError,
        json.JSONDecodeError,
        FileNotFoundError,
        TimeoutError,
    ):
        pass

    return entries


def collect_all() -> dict:
    """Return the current Windows persistence snapshot."""
    return {
        "T1547.001": get_run_keys(),
        "T1053.005": get_scheduled_tasks(),
        "T1543.003": get_services(),
    }
