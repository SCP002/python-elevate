import ctypes
import sys
import time
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    import _win32typing  # pyright: ignore[reportMissingModuleSource]

import psutil
import win32api
import win32con
import win32security
import win32service


def is_admin() -> bool:
    """
    Check if the current process is running with administrator privileges.

    Returns:
        bool: True if running as administrator, False otherwise
    """
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def elevate_to_admin(*, windows_terminal: bool) -> None:
    """
    Attempt to elevate the current process to run with administrator privileges.
    Will trigger UAC prompt if not already elevated. Exits current process on success.

    Args:
        windows_terminal: Whether to elevate to Windows Terminal app or not.
    """
    if is_admin():
        return

    if windows_terminal:
        app = "wt.exe"
        args = [sys.executable] + sys.argv
    else:
        app = sys.executable
        args = sys.argv

    params = " ".join([f'"{arg}"' for arg in args])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", app, params, None, 1)
    sys.exit(0)


def is_system() -> bool:
    """
    Check if the current process is running with SYSTEM privileges.

    Returns:
        bool: True if running as SYSTEM, False otherwise.
    """
    try:
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
        return _is_user_sid_equals(system_sid)
    except Exception as e:
        print(f"Unable to check if process is run as SYSTEM: {e}", file=sys.stderr)
        return False


def elevate_to_system() -> None:
    """
    Attempt to elevate the current process to run with SYSTEM privileges.
    Will trigger UAC prompt if not already elevated. Exits current process on success.
    """
    if is_system():
        return

    elevate_to_admin(windows_terminal=False)

    try:
        winlogon_pid = _get_pid_by_process_name("winlogon.exe")
        h_duplicate_token = _duplicate_token_from_pid(winlogon_pid)
        _start_process_with_user_token(h_duplicate_token, sys.executable, sys.argv)
    finally:
        sys.exit(0)


def is_trusted_installer() -> bool:
    """
    Check if current process has TrustedInstaller permissions by verifying group membership.

    Returns:
        bool: True if current process has TrustedInstaller permissions.
    """
    try:
        trusted_installer_sid = win32security.ConvertStringSidToSid(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        )

        token_groups = _get_current_token_groups()
        if token_groups is None:
            return False

        return _is_sid_enabled_in_groups(token_groups, trusted_installer_sid)
    except Exception as e:
        print(f"Unable to check if process is run as TrustedInstaller: {e}", file=sys.stderr)
        return False


def elevate_to_trusted_installer() -> None:
    """
    Attempt to elevate the current process to run with TrustedInstaller privileges.
    Will trigger UAC prompt if not already elevated. Exits current process on success.
    """
    if is_trusted_installer():
        return

    elevate_to_system()

    try:
        trusted_installer_pid = _get_service_process_pid("TrustedInstaller")
        h_duplicate_token = _duplicate_token_from_pid(trusted_installer_pid)
        _start_process_with_user_token(h_duplicate_token, sys.executable, sys.argv)
    finally:
        sys.exit(0)


def _is_user_sid_equals(target_sid: "_win32typing.PySID") -> bool:
    """
    Check if user SID of current process equals to target SID.

    Args:
        target_sid: SID to check against.

    Returns:
        True if equals, False othewise.
    """
    try:
        h_process = win32api.GetCurrentProcess()
        h_token = win32security.OpenProcessToken(h_process, win32con.TOKEN_QUERY)
        token_info = win32security.GetTokenInformation(h_token, win32security.TokenUser)
        user_sid: "_win32typing.PySID" = token_info[0]
        return user_sid == target_sid
    except Exception as e:
        print(f"Unable get user SID: {e}", file=sys.stderr)
        return False


def _duplicate_token_from_pid(pid: int) -> ctypes.c_void_p:
    """
    Duplicate user token from process with given PID.

    Returns:
        Duplicated user token handle.
    """
    print(f"Attempting to duplicate token of PID {pid}")

    h_process = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
    if not h_process:
        error = ctypes.GetLastError()
        raise RuntimeError(f"Failed to open process: {error}")

    h_token = ctypes.c_void_p(0)
    try:
        if not ctypes.windll.advapi32.OpenProcessToken(
            h_process, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY, ctypes.byref(h_token)
        ):
            error = ctypes.GetLastError()
            raise RuntimeError(f"Failed to open process token: {error}")
    finally:
        ctypes.windll.kernel32.CloseHandle(h_process)

    try:
        h_duplicate_token = ctypes.c_void_p(0)
        if not ctypes.windll.advapi32.DuplicateTokenEx(
            h_token,
            win32con.TOKEN_ALL_ACCESS,
            None,
            win32security.SecurityImpersonation,
            win32security.TokenPrimary,
            ctypes.byref(h_duplicate_token),
        ):
            error = ctypes.GetLastError()
            raise RuntimeError(f"Failed to duplicate process token: {error}")

        return h_duplicate_token
    finally:
        ctypes.windll.kernel32.CloseHandle(h_token)


def _start_process_with_user_token(user_token: ctypes.c_void_p, executable: str, args: list[str]) -> None:
    """
    Starts a new process using the specified user token, impersonating user.

    Args:
        user_token: The handle to the user token obtained from another process.
        executable: The path to the executable file to run.
        args: A list of command-line arguments to pass to the executable.

    Returns:
        None
    """

    class StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("lpReserved", ctypes.c_char_p),
            ("lpDesktop", ctypes.c_char_p),
            ("lpTitle", ctypes.c_char_p),
            ("dwX", ctypes.c_ulong),
            ("dwY", ctypes.c_ulong),
            ("dwXSize", ctypes.c_ulong),
            ("dwYSize", ctypes.c_ulong),
            ("dwXCountChars", ctypes.c_ulong),
            ("dwYCountChars", ctypes.c_ulong),
            ("dwFillAttribute", ctypes.c_ulong),
            ("dwFlags", ctypes.c_ulong),
            ("wShowWindow", ctypes.c_ushort),
            ("cbReserved2", ctypes.c_ushort),
            ("lpReserved2", ctypes.c_char_p),
            ("hStdInput", ctypes.c_void_p),
            ("hStdOutput", ctypes.c_void_p),
            ("hStdError", ctypes.c_void_p),
        ]

    class ProcessInformation(ctypes.Structure):
        _fields_ = [
            ("hProcess", ctypes.c_void_p),
            ("hThread", ctypes.c_void_p),
            ("dwProcessId", ctypes.c_ulong),
            ("dwThreadId", ctypes.c_ulong),
        ]

    startup_info = StartupInfo()
    startup_info.cb = ctypes.sizeof(StartupInfo)
    process_info = ProcessInformation()

    print("Attempting to create new process using user token")
    params = " ".join([f'"{arg}"' for arg in args])

    try:
        command_unicode = ctypes.create_unicode_buffer(executable + " " + params)
        LOGON_WITH_PROFILE = 0x00000001

        if not ctypes.windll.advapi32.CreateProcessWithTokenW(
            user_token,  # User token
            LOGON_WITH_PROFILE,  # Logon flags
            None,  # Application name
            command_unicode,  # Command line
            win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS,  # Creation flags
            None,  # Environment
            None,  # Current directory
            ctypes.byref(startup_info),
            ctypes.byref(process_info),
        ):
            error = ctypes.GetLastError()
            raise RuntimeError(f"Unable to create process with token: {error}")

        pid = process_info.dwProcessId
        print(f"Process is started with PID: {pid}")
    finally:
        ctypes.windll.kernel32.CloseHandle(user_token)
        ctypes.windll.kernel32.CloseHandle(process_info.hProcess)
        ctypes.windll.kernel32.CloseHandle(process_info.hThread)


def _get_service_process_pid(service_name: str) -> int:
    """
    Get PID of the process associated with the service.
    It starts the service if it's not currently running.

    Args:
        service_name: Name of the service.

    Returns:
        PID of the process associated with the service.
    """
    scm_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    if not scm_handle:
        raise RuntimeError("Failed to open service manager")

    try:
        service_handle = win32service.OpenService(
            scm_handle, service_name, win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_START
        )
        if not service_handle:
            raise RuntimeError(f"Failed to open {service_name} service")

        try:
            status = cast(dict[str, int], win32service.QueryServiceStatusEx(service_handle))

            if status["CurrentState"] != win32service.SERVICE_RUNNING:
                win32service.StartService(service_handle, None)

                # Wait for service to start (max 10 seconds)
                for _ in range(10):
                    time.sleep(1)
                    status = cast(dict[str, int], win32service.QueryServiceStatusEx(service_handle))
                    if status["CurrentState"] == win32service.SERVICE_RUNNING:
                        break
                else:
                    raise RuntimeError(f"{service_name} service failed to start")

            return int(status["ProcessId"])
        finally:
            win32service.CloseServiceHandle(service_handle)
    finally:
        win32service.CloseServiceHandle(scm_handle)


def _get_current_token_groups() -> list[tuple["_win32typing.PySID", int]] | None:
    """
    Retrieve the group SIDs and their attributes from the current process token.

    Returns:
        A list of tuples (group_sid, attributes) on success, None on failure.
    """
    try:
        process_handle = win32api.GetCurrentProcess()
        token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_QUERY)
        return cast(
            list[tuple["_win32typing.PySID", int]],
            win32security.GetTokenInformation(token_handle, win32security.TokenGroups),
        )
    except Exception as e:
        print(f"Error retrieving token groups: {e}", file=sys.stderr)
        return None


def _is_sid_enabled_in_groups(
    groups: list[tuple["_win32typing.PySID", int]], sid_to_check: "_win32typing.PySID"
) -> bool:
    """
    Check if the specified SID is present and enabled in the token groups.

    Args:
        groups: List of groups to check against tuples of (group_sid, attributes).
        sid_to_check: pywin32.PySID instance to search in group SIDs.

    Returns:
        True if found with SE_GROUP_ENABLED and not SE_GROUP_USE_FOR_DENY_ONLY.
    """
    for group in groups:
        group_sid, attributes = group
        if group_sid == sid_to_check:
            # Check if the group is enabled and not deny-only
            if (
                attributes & win32security.SE_GROUP_ENABLED
                and not attributes & win32security.SE_GROUP_USE_FOR_DENY_ONLY
            ):
                return True
    return False


def _get_pid_by_process_name(name: str) -> int:
    """
    Get PID of the first process with the given name.

    Args:
        name: Process executable name to match.

    Returns:
        PID of the process.

    Raises:
        psutil.NoSuchProcess: If no matching process found.
    """
    pids = _get_pids_by_process_name(name)
    if pids:
        return pids[0]
    raise psutil.NoSuchProcess(0, f"Unable to find process {name}")


def _get_pids_by_process_name(name: str) -> list[int]:
    """
    Return a list of PID's for processes with the given executable name.

    Args:
        name: Process executable name to match.

    Returns:
        List of matching process PID's.
    """
    pids: list[int] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] == name:
                pids.append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids
