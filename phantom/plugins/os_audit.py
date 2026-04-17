"""OS-level security audit plugin.

Runs a local system audit only when the target resolves to the loopback
address (127.x.x.x) or is explicitly 'localhost'.  For any other target
the plugin exits immediately with zero findings, preserving the
non-destructive / non-intrusive design contract.

Platform strategy
-----------------
Linux  → lynis (if available) then /proc + systemd + SUID enumeration
macOS  → system_profiler + SIP check + launchd + firewall status
Windows → PowerShell: services, local users, audit policy, SMB config
"""
from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import sys
from typing import Any

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext

_SYSTEM = platform.system()  # "Linux" | "Darwin" | "Windows"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(*args: str, timeout: int = 15) -> str:
    """Run a command, return stdout, never raise."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _is_local(target: NormalizedTarget) -> bool:
    host = target.hostname or target.ip or target.raw
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        addr = socket.getaddrinfo(host, None)[0][4][0]
        return ipaddress.ip_address(addr).is_loopback
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Linux audit
# ---------------------------------------------------------------------------

def _linux_audit(target_label: str, timeout: float) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    obs: dict[str, Any] = {"os_audit": {}}

    # --- Lynis ---
    if shutil.which("lynis"):
        raw = _run("lynis", "audit", "system", "--quick", "--no-colors",
                   "--report-file", "/dev/null", timeout=120)
        warnings = re.findall(r"^\s*\[WARNING\]\s*(.+)$", raw, re.MULTILINE)
        suggestions = re.findall(r"^\s*\[SUGGESTION\]\s*(.+)$", raw, re.MULTILINE)
        hardening_score_match = re.search(r"Hardening index\s*[:\-]\s*(\d+)", raw)
        hardening_score = int(hardening_score_match.group(1)) if hardening_score_match else None

        obs["os_audit"]["lynis_warnings"] = warnings
        obs["os_audit"]["lynis_suggestions"] = suggestions[:20]
        if hardening_score is not None:
            obs["os_audit"]["hardening_index"] = hardening_score

        for w in warnings[:10]:
            findings.append(Finding(
                title=f"Lynis warning: {w[:80]}",
                description=f"Lynis reported a warning during system audit: {w}",
                category="os_hardening",
                severity="medium",
                score=5.5,
                target=target_label,
                source_module="os_audit",
                evidence={"lynis_output": w},
                recommendation="Review lynis output: sudo lynis audit system",
            ))
        if hardening_score is not None and hardening_score < 60:
            severity = "high" if hardening_score < 40 else "medium"
            score = 7.0 if hardening_score < 40 else 5.0
            findings.append(Finding(
                title=f"Low system hardening index ({hardening_score}/100)",
                description="Lynis measured a below-threshold hardening index, indicating significant misconfigurations.",
                category="os_hardening",
                severity=severity,
                score=score,
                target=target_label,
                source_module="os_audit",
                evidence={"hardening_index": hardening_score},
                recommendation="Follow Lynis suggestions: sudo lynis audit system",
            ))
        if raw:
            return findings, obs

    # --- Fallback: manual Linux checks ---
    # 1. World-writable SUID binaries
    suid_out = _run("find", "/usr", "/bin", "/sbin", "-perm", "-4000",
                    "-type", "f", "-ls", timeout=20)
    suid_files = [l.split()[-1] for l in suid_out.splitlines() if l.strip()]
    obs["os_audit"]["suid_files"] = suid_files
    if len(suid_files) > 15:
        findings.append(Finding(
            title=f"Excessive SUID binaries ({len(suid_files)} found)",
            description="Large number of SUID root binaries increases local privilege escalation risk.",
            category="os_hardening",
            severity="medium",
            score=5.0,
            target=target_label,
            source_module="os_audit",
            evidence={"count": len(suid_files), "sample": suid_files[:5]},
            recommendation="Audit SUID binaries: find / -perm -4000 -type f 2>/dev/null",
        ))

    # 2. Open listening ports (ss)
    ss_out = _run("ss", "-tlnp", timeout=10) or _run("netstat", "-tlnp", timeout=10)
    obs["os_audit"]["listening_services"] = ss_out[:2000]

    # 3. Password policy
    login_defs = ""
    try:
        import pathlib
        login_defs = pathlib.Path("/etc/login.defs").read_text(errors="replace")
    except Exception:
        pass
    max_days_match = re.search(r"^PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE)
    min_len_match = re.search(r"^PASS_MIN_LEN\s+(\d+)", login_defs, re.MULTILINE)
    if max_days_match:
        max_days = int(max_days_match.group(1))
        obs["os_audit"]["pass_max_days"] = max_days
        if max_days > 90 or max_days == 99999:
            findings.append(Finding(
                title="Weak password expiration policy",
                description=f"PASS_MAX_DAYS is {max_days} — passwords do not expire frequently enough.",
                category="os_hardening",
                severity="medium",
                score=4.5,
                target=target_label,
                source_module="os_audit",
                evidence={"pass_max_days": max_days},
                recommendation="Set PASS_MAX_DAYS to 90 or less in /etc/login.defs",
            ))
    if min_len_match:
        min_len = int(min_len_match.group(1))
        obs["os_audit"]["pass_min_len"] = min_len
        if min_len < 12:
            findings.append(Finding(
                title="Minimum password length too short",
                description=f"PASS_MIN_LEN is {min_len}, below the recommended 12 characters.",
                category="os_hardening",
                severity="medium",
                score=4.0,
                target=target_label,
                source_module="os_audit",
                evidence={"pass_min_len": min_len},
                recommendation="Set PASS_MIN_LEN to 12+ in /etc/login.defs",
            ))

    # 4. Passwordless sudo
    sudoers_out = _run("grep", "-r", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d/",
                       "--include=*", timeout=5)
    if sudoers_out:
        findings.append(Finding(
            title="NOPASSWD sudo rules detected",
            description="One or more sudoers rules allow privilege escalation without password authentication.",
            category="privilege_escalation",
            severity="high",
            score=7.5,
            target=target_label,
            source_module="os_audit",
            evidence={"sudoers_matches": sudoers_out[:500]},
            recommendation="Remove NOPASSWD entries from /etc/sudoers unless strictly required.",
        ))

    # 5. SSH root login
    ssh_config = _run("sshd", "-T", timeout=5)
    if "permitrootlogin yes" in ssh_config.lower():
        findings.append(Finding(
            title="SSH root login enabled",
            description="sshd is configured to allow direct root login, increasing brute-force and lateral movement risk.",
            category="os_hardening",
            severity="high",
            score=7.0,
            target=target_label,
            source_module="os_audit",
            evidence={"sshd_config": "PermitRootLogin yes"},
            recommendation="Set PermitRootLogin no in /etc/ssh/sshd_config",
        ))

    return findings, obs


# ---------------------------------------------------------------------------
# macOS audit
# ---------------------------------------------------------------------------

def _macos_audit(target_label: str, timeout: float) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    obs: dict[str, Any] = {"os_audit": {}}

    # 1. SIP (System Integrity Protection)
    sip_out = _run("csrutil", "status", timeout=5)
    obs["os_audit"]["sip_status"] = sip_out
    if "disabled" in sip_out.lower():
        findings.append(Finding(
            title="System Integrity Protection (SIP) is disabled",
            description="SIP protects system files from modification. Disabling it exposes the system to rootkits and persistent malware.",
            category="os_hardening",
            severity="high",
            score=7.5,
            target=target_label,
            source_module="os_audit",
            evidence={"sip_status": sip_out},
            recommendation="Re-enable SIP: boot to Recovery OS and run 'csrutil enable'.",
        ))

    # 2. Firewall
    fw_out = _run("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate", timeout=5)
    obs["os_audit"]["firewall_status"] = fw_out
    if "disabled" in fw_out.lower():
        findings.append(Finding(
            title="macOS Application Firewall is disabled",
            description="The built-in application firewall is off, allowing all inbound connections.",
            category="os_hardening",
            severity="medium",
            score=5.5,
            target=target_label,
            source_module="os_audit",
            evidence={"firewall": fw_out},
            recommendation="Enable via System Settings > Network > Firewall, or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
        ))

    # 3. FileVault (disk encryption)
    fv_out = _run("fdesetup", "status", timeout=5)
    obs["os_audit"]["filevault_status"] = fv_out
    if "off" in fv_out.lower():
        findings.append(Finding(
            title="FileVault disk encryption is disabled",
            description="Full-disk encryption is not enabled. Physical access or stolen hardware exposes all data.",
            category="os_hardening",
            severity="medium",
            score=5.0,
            target=target_label,
            source_module="os_audit",
            evidence={"filevault": fv_out},
            recommendation="Enable FileVault in System Settings > Privacy & Security.",
        ))

    # 4. Gatekeeper
    gk_out = _run("spctl", "--status", timeout=5)
    obs["os_audit"]["gatekeeper_status"] = gk_out
    if "disabled" in gk_out.lower():
        findings.append(Finding(
            title="Gatekeeper is disabled",
            description="Gatekeeper no longer verifies app signatures, allowing unsigned/malicious apps to run.",
            category="os_hardening",
            severity="high",
            score=7.0,
            target=target_label,
            source_module="os_audit",
            evidence={"gatekeeper": gk_out},
            recommendation="Re-enable: sudo spctl --master-enable",
        ))

    # 5. Auto-update
    au_out = _run("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
                  "AutomaticCheckEnabled", timeout=5)
    obs["os_audit"]["auto_update"] = au_out
    if au_out.strip() == "0":
        findings.append(Finding(
            title="Automatic macOS updates are disabled",
            description="Security patches are not applied automatically, leaving known vulnerabilities unpatched.",
            category="os_hardening",
            severity="medium",
            score=4.5,
            target=target_label,
            source_module="os_audit",
            evidence={"AutomaticCheckEnabled": "0"},
            recommendation="Enable: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true",
        ))

    # 6. SSH root login
    sshd_config = ""
    try:
        import pathlib
        sshd_config = pathlib.Path("/etc/ssh/sshd_config").read_text(errors="replace")
    except Exception:
        pass
    if re.search(r"^PermitRootLogin\s+yes", sshd_config, re.MULTILINE | re.IGNORECASE):
        findings.append(Finding(
            title="SSH root login enabled",
            description="sshd allows direct root login.",
            category="os_hardening",
            severity="high",
            score=7.0,
            target=target_label,
            source_module="os_audit",
            evidence={"sshd_config": "PermitRootLogin yes"},
            recommendation="Set PermitRootLogin no in /etc/ssh/sshd_config",
        ))

    return findings, obs


# ---------------------------------------------------------------------------
# Windows audit
# ---------------------------------------------------------------------------

def _ps(script: str, timeout: int = 20) -> str:
    """Run a PowerShell command and return stdout (UTF-8, never raises)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-OutputFormat", "Text", "-Command", script],
            capture_output=True,
            timeout=timeout,
            errors="replace",
            encoding="utf-8",
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _ps_bool(script: str) -> bool | None:
    """Return True/False/None from a PowerShell boolean query."""
    out = _ps(script).strip().lower()
    if out == "true":
        return True
    if out == "false":
        return False
    return None


def _ps_int(script: str) -> int | None:
    """Return an int from a PowerShell numeric query."""
    out = _ps(script).strip()
    try:
        return int(out)
    except (ValueError, TypeError):
        return None


def _windows_audit(target_label: str, timeout: float) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    obs: dict[str, Any] = {"os_audit": {}}

    # 1. Password policy (via secedit export — locale-agnostic)
    min_len = _ps_int(
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' "
        "-Name MinimumPasswordLength -ErrorAction SilentlyContinue).MinimumPasswordLength"
    )
    # Fallback: local account policy via net accounts parsed with regex on numeric part
    if min_len is None:
        min_len = _ps_int(
            "$p = (Get-LocalUser | Where-Object Enabled -eq $true | Measure-Object).Count; "
            "try { $pol = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'); "
            "$null } catch {}; "
            "[System.Security.Principal.NTAccount]::new(''); $null"
        )
    # Use Get-ADDefaultDomainPasswordPolicy if domain, else registry
    pw_max_age_days = _ps_int(
        "$k='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';"
        "try{[int]((Get-ItemProperty $k -ErrorAction Stop).PasswordExpiryWarning)}catch{$null}"
    )
    # Simplest reliable approach for local policy:
    min_pw_len = _ps_int(
        "try { Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop;"
        "$ctx=[System.DirectoryServices.AccountManagement.PrincipalContext]::new("
        "[System.DirectoryServices.AccountManagement.ContextType]::Machine);"
        "$pol=[System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx,'Administrator');"
        "$null } catch {$null}; $null"
    )
    # Best effort: read from secedit
    secedit_out = _ps(
        "$tmp=[System.IO.Path]::GetTempFileName();"
        "secedit /export /cfg $tmp /quiet 2>$null;"
        "if(Test-Path $tmp){ Get-Content $tmp; Remove-Item $tmp -Force }",
        timeout=15
    )
    obs["os_audit"]["secedit"] = secedit_out[:1000]
    if secedit_out:
        ml_match = re.search(r"MinimumPasswordLength\s*=\s*(\d+)", secedit_out)
        ma_match = re.search(r"MaximumPasswordAge\s*=\s*(-?\d+)", secedit_out)
        if ml_match:
            min_pw_len = int(ml_match.group(1))
            obs["os_audit"]["min_password_length"] = min_pw_len
            if min_pw_len < 12:
                findings.append(Finding(
                    title=f"Minimum password length too short ({min_pw_len})",
                    description=f"Local security policy requires only {min_pw_len} characters (recommended ≥12).",
                    category="os_hardening", severity="medium", score=4.5,
                    target=target_label, source_module="os_audit",
                    evidence={"min_password_length": min_pw_len},
                    recommendation="Increase via: net accounts /minpwlen:12",
                ))
        if ma_match:
            max_age = int(ma_match.group(1))
            obs["os_audit"]["max_password_age_days"] = max_age
            if max_age < 0 or max_age == 0:  # -1 or 0 = never expires
                findings.append(Finding(
                    title="Passwords never expire (local policy)",
                    description="Local security policy has no maximum password age.",
                    category="os_hardening", severity="medium", score=4.0,
                    target=target_label, source_module="os_audit",
                    evidence={"max_password_age": "unlimited"},
                    recommendation="Set: net accounts /maxpwage:90",
                ))

    # 2. Guest account (PowerShell locale-agnostic)
    guest_enabled = _ps_bool("(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")
    if guest_enabled is None:
        guest_enabled = _ps_bool("(Get-LocalUser | Where-Object {$_.Name -match 'Guest|Invité'} | Select-Object -First 1).Enabled")
    obs["os_audit"]["guest_enabled"] = guest_enabled
    if guest_enabled:
        findings.append(Finding(
            title="Built-in Guest account is enabled",
            description="The Guest account is active, allowing unauthenticated local access.",
            category="os_hardening", severity="high", score=7.0,
            target=target_label, source_module="os_audit",
            evidence={"guest_enabled": True},
            recommendation="Disable: Disable-LocalUser -Name 'Guest'",
        ))

    # 3. Windows Firewall
    fw_out = _ps("Get-NetFirewallProfile | ForEach-Object { $_.Name + '=' + $_.Enabled }")
    obs["os_audit"]["firewall"] = fw_out
    disabled = [line.split("=")[0] for line in fw_out.splitlines() if "=False" in line]
    if disabled:
        findings.append(Finding(
            title=f"Windows Firewall disabled: {', '.join(disabled)}",
            description="One or more Firewall profiles are off, removing network boundary control.",
            category="os_hardening", severity="high", score=7.5,
            target=target_label, source_module="os_audit",
            evidence={"disabled_profiles": disabled},
            recommendation="Enable: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        ))

    # 4. SMBv1
    smb1 = _ps_bool("(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol")
    obs["os_audit"]["smb1_enabled"] = smb1
    if smb1:
        findings.append(Finding(
            title="SMBv1 enabled — EternalBlue attack surface",
            description="SMBv1 contains critical vulnerabilities (MS17-010/EternalBlue) enabling unauthenticated RCE.",
            category="vulnerability", severity="critical", score=9.5,
            target=target_label, source_module="os_audit",
            evidence={"smb1": True},
            recommendation="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        ))

    # 5. RDP NLA
    nla = _ps_int(
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server"
        "\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue)"
        ".UserAuthentication"
    )
    obs["os_audit"]["rdp_nla"] = nla
    if nla == 0:
        findings.append(Finding(
            title="RDP Network Level Authentication (NLA) disabled",
            description="RDP exposes the login screen without NLA, enabling credential brute-force before authentication.",
            category="os_hardening", severity="high", score=7.0,
            target=target_label, source_module="os_audit",
            evidence={"UserAuthentication": 0},
            recommendation="Enable NLA: Set-ItemProperty 'HKLM:\\...\\RDP-Tcp' UserAuthentication 1",
        ))

    # 6. Defender real-time protection
    rtp = _ps_bool("(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled")
    obs["os_audit"]["defender_rtp"] = rtp
    if rtp is False:
        findings.append(Finding(
            title="Windows Defender real-time protection disabled",
            description="Malware can execute without detection while real-time protection is off.",
            category="os_hardening", severity="high", score=7.5,
            target=target_label, source_module="os_audit",
            evidence={"RealTimeProtectionEnabled": False},
            recommendation="Enable: Set-MpPreference -DisableRealtimeMonitoring $false",
        ))

    # 7. Auto-logon
    autologon = _ps_int(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'"
        " -Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon"
    )
    obs["os_audit"]["autologon"] = autologon
    if autologon == 1:
        findings.append(Finding(
            title="Windows auto-logon is enabled",
            description="Credentials stored in registry allow automatic logon — physical or remote access bypasses authentication.",
            category="credential_exposure", severity="critical", score=9.0,
            target=target_label, source_module="os_audit",
            evidence={"AutoAdminLogon": 1},
            recommendation="Disable: Set-ItemProperty 'HKLM:\\...\\Winlogon' AutoAdminLogon 0",
        ))

    # 8. PowerShell execution policy
    ep = _ps("(Get-ExecutionPolicy -Scope LocalMachine) -as [string]")
    obs["os_audit"]["ps_execution_policy"] = ep
    if ep.lower() in {"unrestricted", "bypass"}:
        findings.append(Finding(
            title=f"PowerShell ExecutionPolicy is {ep} (LocalMachine)",
            description="Unrestricted or Bypass execution policy allows any script to run without restriction.",
            category="os_hardening", severity="medium", score=5.0,
            target=target_label, source_module="os_audit",
            evidence={"ExecutionPolicy": ep},
            recommendation="Set: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
        ))

    return findings, obs


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class OsAuditPlugin(BasePlugin):
    name = "os_audit"
    action_type = "analysis"
    description = (
        "Local OS security audit. Runs Lynis on Linux, "
        "built-in checks on macOS (SIP/FileVault/Gatekeeper), "
        "and PowerShell policy checks on Windows. "
        "Only executes when the target is localhost / 127.x."
    )

    def execute(
        self,
        context: PluginContext,
        target: NormalizedTarget,
        observations: dict[str, Any],
    ) -> ModuleResult:
        if not _is_local(target):
            return ModuleResult(findings=[], observations={"os_audit": {"skipped": "non-local target"}})

        timeout = context.config.roe.network_timeout_seconds * 5  # generous for local commands

        if _SYSTEM == "Linux":
            findings, obs = _linux_audit(target.label(), timeout)
        elif _SYSTEM == "Darwin":
            findings, obs = _macos_audit(target.label(), timeout)
        elif _SYSTEM == "Windows":
            findings, obs = _windows_audit(target.label(), timeout)
        else:
            return ModuleResult(findings=[], observations={"os_audit": {"skipped": f"unsupported OS: {_SYSTEM}"}})

        obs["os_audit"]["platform"] = _SYSTEM
        return ModuleResult(findings=findings, observations=obs)
