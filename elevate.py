import ctypes
import ctypes.wintypes
import sys
import time
from collections.abc import Iterator
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    import _win32typing  # pyright: ignore[reportMissingModuleSource]

import psutil
import pywintypes
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
    win32api.ShellExecute(0, "runas", app, params, "", win32con.SW_SHOWNORMAL)
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
    except pywintypes.error as e:
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
    except pywintypes.error as e:
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
        user_sid: _win32typing.PySID = token_info[0]
        return user_sid == target_sid
    except pywintypes.error as e:
        print(f"Unable get user SID: {e}", file=sys.stderr)
        return False


def _duplicate_token_from_pid(pid: int) -> int:
    """
    Duplicate user token from process with given PID.

    Returns:
        Duplicated user token handle.

    Raises:
        pywintypes.error: If the process or its token cannot be opened or duplicated.
    """
    print(f"Attempting to duplicate token of PID {pid}")

    # PyHANDLE objects close themselves when garbage-collected, so no manual cleanup is needed.
    h_process = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
    h_token = win32security.OpenProcessToken(h_process, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY)
    return win32security.DuplicateTokenEx(
        h_token,
        win32security.SecurityImpersonation,
        win32con.TOKEN_ALL_ACCESS,
        win32security.TokenPrimary,
        None,
    )


class _StartupInfoW(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("lpReserved", ctypes.wintypes.LPWSTR),
        ("lpDesktop", ctypes.wintypes.LPWSTR),
        ("lpTitle", ctypes.wintypes.LPWSTR),
        ("dwX", ctypes.wintypes.DWORD),
        ("dwY", ctypes.wintypes.DWORD),
        ("dwXSize", ctypes.wintypes.DWORD),
        ("dwYSize", ctypes.wintypes.DWORD),
        ("dwXCountChars", ctypes.wintypes.DWORD),
        ("dwYCountChars", ctypes.wintypes.DWORD),
        ("dwFillAttribute", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("wShowWindow", ctypes.wintypes.WORD),
        ("cbReserved2", ctypes.wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", ctypes.wintypes.HANDLE),
        ("hStdOutput", ctypes.wintypes.HANDLE),
        ("hStdError", ctypes.wintypes.HANDLE),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.wintypes.HANDLE),
        ("hThread", ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
    ]


def _start_process_with_user_token(user_token: int, executable: str, args: list[str]) -> None:
    """
    Starts a new process using the specified user token, impersonating user.

    Args:
        user_token: The handle to the user token obtained from another process.
        executable: The path to the executable file to run.
        args: A list of command-line arguments to pass to the executable.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    create_process_with_token = advapi32.CreateProcessWithTokenW
    create_process_with_token.argtypes = [
        ctypes.wintypes.HANDLE,  # hToken
        ctypes.wintypes.DWORD,  # dwLogonFlags
        ctypes.wintypes.LPCWSTR,  # lpApplicationName
        ctypes.wintypes.LPWSTR,  # lpCommandLine
        ctypes.wintypes.DWORD,  # dwCreationFlags
        ctypes.wintypes.LPVOID,  # lpEnvironment
        ctypes.wintypes.LPCWSTR,  # lpCurrentDirectory
        ctypes.POINTER(_StartupInfoW),
        ctypes.POINTER(_ProcessInformation),
    ]
    create_process_with_token.restype = ctypes.wintypes.BOOL

    startup_info = _StartupInfoW()
    startup_info.cb = ctypes.sizeof(_StartupInfoW)
    process_info = _ProcessInformation()

    print("Attempting to create new process using user token")
    params = " ".join([f'"{arg}"' for arg in args])
    command_line = ctypes.create_unicode_buffer(f'"{executable}" {params}')
    LOGON_WITH_PROFILE = 0x00000001

    try:
        if not create_process_with_token(
            int(user_token),  # User token
            LOGON_WITH_PROFILE,  # Logon flags
            None,  # Application name
            command_line,  # Command line
            win32con.CREATE_NEW_CONSOLE | win32con.NORMAL_PRIORITY_CLASS,  # Creation flags
            None,  # Environment
            None,  # Current directory
            ctypes.byref(startup_info),
            ctypes.byref(process_info),
        ):
            error = ctypes.get_last_error()
            raise RuntimeError(f"Unable to create process with token: {error}")

        print(f"Process is started with PID: {process_info.dwProcessId}")
    finally:
        if process_info.hProcess:
            win32api.CloseHandle(process_info.hProcess)
        if process_info.hThread:
            win32api.CloseHandle(process_info.hThread)


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

            return status["ProcessId"]
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
    except pywintypes.error as e:
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
        # Check if the group is enabled and not deny-only
        if group_sid == sid_to_check and (
            attributes & win32security.SE_GROUP_ENABLED and not attributes & win32security.SE_GROUP_USE_FOR_DENY_ONLY
        ):
            return True
    return False


def _iter_processes_by_name(name: str) -> Iterator[psutil.Process]:
    # process_iter() with attrs skips vanished processes and sets inaccessible attrs to None
    for proc in psutil.process_iter(["name"]):
        if proc.info["name"] == name:
            yield proc


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
    for proc in _iter_processes_by_name(name):
        return proc.pid
    raise psutil.NoSuchProcess(0, name, msg="Unable to find process")
