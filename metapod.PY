#!/usr/bin/env python3
"""
metapod_hardening_final.py

Metapod Hardening Tool — Final updated edition.

Run as Administrator. If not elevated, the script will attempt to relaunch itself with elevation.
"""

import os
import sys
import ctypes
import subprocess
import threading
import datetime
import json
from queue import Queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ------------------------- SETTINGS (with descriptions) -------------------------
# Each entry: id, name, enable cmd, disable cmd, desc
# Note: registry strings use double backslashes where necessary inside Python strings.
SETTINGS = {
    "File Associations": [
        {"id": "hta_notepad", "name": "Harden .hta files (open in Notepad)",
         "enable": 'ftype htafile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"',
         "disable": 'ftype htafile="%SystemRoot%\\System32\\mshta.exe" "%1" %*',
         "desc": "Open .hta files in Notepad rather than mshta.exe to prevent HTML application execution."},
        {"id": "wsh_notepad", "name": "Harden .wsh files (open in Notepad)",
         "enable": 'ftype wshfile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"',
         "disable": 'ftype wshfile="%SystemRoot%\\System32\\WScript.exe" "%1" %*',
         "desc": "Redirect .wsh file handling to Notepad to avoid automatic script execution."},
        {"id": "wsf_notepad", "name": "Harden .wsf files (open in Notepad)",
         "enable": 'ftype wsffile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"',
         "disable": 'ftype wsffile="%SystemRoot%\\System32\\WScript.exe" "%1" %*',
         "desc": "Neutralize .wsf script files by opening them in an editor."},
        {"id": "bat_notepad", "name": "Harden .bat files (open in Notepad)",
         "enable": 'ftype batfile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"',
         "disable": 'ftype batfile="%1" %*',
         "desc": "Open batch files in Notepad instead of executing them by double-click."},
        {"id": "js_notepad", "name": "Harden .js files (open in Notepad)",
         "enable": 'ftype jsfile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"',
         "disable": 'ftype jsfile="%SystemRoot%\\System32\\WScript.exe" "%1" %*',
         "desc": "Open .js files in an editor instead of executing via WScript."},
        {"id": "jse_notepad", "name": "Harden .jse files (open in Notepad)",
         "enable": 'ftype jsefile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"',
         "disable": 'ftype jsefile="%SystemRoot%\\System32\\WScript.exe" "%1" %*',
         "desc": "Prevent .jse (encoded javascript) from executing directly."},
        {"id": "vbe_notepad", "name": "Harden .vbe files (open in Notepad)",
         "enable": 'ftype vbefile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"',
         "disable": 'ftype vbefile="%SystemRoot%\\System32\\WScript.exe" "%1" %*',
         "desc": "Open encoded VBScript files in editor rather than executing."},
        {"id": "vbs_notepad", "name": "Harden .vbs files (open in Notepad)",
         "enable": 'ftype vbsfile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"',
         "disable": 'ftype vbsfile="%SystemRoot%\\System32\\WScript.exe" "%1" %*',
         "desc": "Open .vbs files in Notepad by default to avoid unintended execution."},
    ],
    "Windows Defender": [
        {"id": "def_sandbox", "name": "Enable Windows Defender Sandboxing",
         "enable": 'setx /M MP_FORCE_USE_SANDBOX 1',
         "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" /v MP_FORCE_USE_SANDBOX /f',
         "desc": "Enable Defender process sandboxing where available to reduce impact of agent exploits."},
        {"id": "def_pua", "name": "Enable PUA Protection",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -PUAProtection Enable"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -PUAProtection Disable"',
         "desc": "Detect and block Potentially Unwanted Applications (PUAs)."},
        {"id": "def_passive", "name": "Enable Defender Periodic Scanning (Passive Mode)",
         "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f',
         "disable": 'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows Defender" /v PassiveMode /f',
         "desc": "Allow Defender periodic scanning even when third-party AV is present."},
        {"id": "def_maps", "name": "Enable Advanced Cloud Protection (MAPS)",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -MAPSReporting Advanced"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -MAPSReporting 0"',
         "desc": "Enable cloud-based protections for improved detections."},
        {"id": "def_samples", "name": "Disable Automatic Sample Submission",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -SubmitSamplesConsent 0"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -SubmitSamplesConsent 1"',
         "desc": "Control automatic sample submission to Microsoft."},
        {"id": "def_elam", "name": "Enable Early Launch Anti-Malware (ELAM)",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f',
         "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch" /v DriverLoadPolicy /f',
         "desc": "Configure ELAM driver load policy for early-boot protection."},
    ],
    "Attack Surface Reduction": [
        {"id": "asr_office_childproc", "name": "Block Office Child Process Creation",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Disabled"',
         "desc": "Prevent Office apps from spawning child processes."},
        {"id": "asr_office_inject", "name": "Block Office Process Injection",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Disabled"',
         "desc": "Mitigate in-memory injection from Office components."},
        {"id": "asr_obfuscated_scripts", "name": "Block Obfuscated Scripts",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Disabled"',
         "desc": "Block obfuscated or packed scripts."},
        {"id": "asr_script_launch_exec", "name": "Block JS/VBScript from Launching Executables",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Disabled"',
         "desc": "Prevent script engines from launching executables."},
        {"id": "asr_psexec_wmi", "name": "Block Processes from PSExec and WMI",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Disabled"',
         "desc": "Reduce lateral movement by blocking PSExec/WMI process launches."},
    ],
    "System-Wide Protections": [
        {"id": "sys_exploit_prot", "name": "Enable System-Wide Exploit Protection (DEP, SEHOP, etc.)",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,TerminateOnError"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-Processmitigation -System -Disable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,TerminateOnError"',
         "desc": "Enable system-level exploit mitigations."},
        {"id": "sys_lsass_ppl", "name": "Harden LSASS Against Credential Dumping",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /f',
         "desc": "Mark LSASS as a protected process to reduce credential dumping risk."},
        {"id": "sys_wdigest", "name": "Disable WDigest Credential Caching",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f',
         "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /f',
         "desc": "Ensure WDigest doesn't keep plaintext credentials in memory."},
        {"id": "sys_safedll", "name": "Enable Safe DLL Search Mode",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v SafeDLLSearchMode /f',
         "desc": "Prioritize system dirs for DLL resolution to mitigate DLL planting."},
        {"id": "sys_uac", "name": "Enable UAC (User Account Control)",
         "enable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f',
         "disable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 0 /f',
         "desc": "Ensure elevation prompts are enforced."},
        {"id": "sys_uac_always", "name": "Set UAC to Always Notify",
         "enable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f',
         "disable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f',
         "desc": "Require full interactive confirmation for admin actions."},
    ],
    "Browser & Office": [
        {"id": "br_edge_smartscreen", "name": "Enable SmartScreen for Edge",
         "enable": 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f',
         "disable": 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f',
         "desc": "Turn on Edge SmartScreen phishing/malicious site protection."},
        {"id": "br_edge_pwdmgr", "name": "Disable Edge Password Manager",
         "enable": 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f',
         "disable": 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main" /v "FormSuggest Passwords" /t REG_SZ /d yes /f',
         "desc": "Disable storing passwords in Edge in policy-managed scenarios."},
        {"id": "br_chrome_siteisolation", "name": "Chrome: Enable Site Isolation (SitePerProcess)",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "SitePerProcess" /f',
         "desc": "Separate renderer processes to mitigate cross-site attacks."},
        {"id": "br_chrome_doh", "name": "Chrome: Enable DNS-over-HTTPS",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d "on" /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "DnsOverHttpsMode" /f',
         "desc": "Encrypt DNS resolution (privacy/integrity) where supported."},
        {"id": "off_disable_macros", "name": "Office: Disable Macros with Notification",
         "enable": 'reg add "HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security" /v vbawarnings /t REG_DWORD /d 4 /f',
         "disable": 'reg add "HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security" /v vbawarnings /t REG_DWORD /d 1 /f',
         "desc": "Block macros by default but allow users to be notified for exceptions."},
    ],
    "Privacy & Logging": [
        {"id": "priv_telemetry", "name": "Set Telemetry to Security Only",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f',
         "disable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 3 /f',
         "desc": "Reduce telemetry to security-only where permitted by policy."},
        {"id": "priv_adid", "name": "Disable Advertising ID",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo" /v DisabledByGroupPolicy /f',
         "desc": "Stop apps from using Advertising ID for tracking."},
        {"id": "priv_location", "name": "Disable Location Data",
         "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" /v Value /t REG_SZ /d Deny /f',
         "disable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" /v Value /t REG_SZ /d Allow /f',
         "desc": "Deny apps access to device location by default."},
        {"id": "priv_bing", "name": "Disable Bing Search in Start Menu",
         "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f',
         "disable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" /v BingSearchEnabled /t REG_DWORD /d 1 /f',
         "desc": "Prevent Start menu search queries from being sent to Bing."},
        {"id": "priv_cortana", "name": "Disable Cortana",
         "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" /v CortanaConsent /t REG_DWORD /d 0 /f',
         "disable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" /v CortanaConsent /t REG_DWORD /d 1 /f',
         "desc": "Disable Cortana to reduce voice/usage telemetry."},
        {"id": "priv_pslog", "name": "Enable PowerShell Script Block Logging",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /f',
         "desc": "Log PowerShell script blocks for detection and auditing."},
        {"id": "priv_audit_cmdline", "name": "Audit: Include Command Line in Process Creation Events",
         "enable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f',
         "desc": "Include command line in process creation events for forensic value."},
    ],
    "Firewall & Network": [
        {"id": "fw_all_on", "name": "Turn on Windows Firewall for All Profiles",
         "enable": 'NetSh Advfirewall set allprofiles state on',
         "disable": 'NetSh Advfirewall set allprofiles state off',
         "desc": "Ensure Windows Firewall is enabled on all profiles."},
        {"id": "fw_block_inbound", "name": "Block All Inbound Connections (Public Profile)",
         "enable": 'netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound',
         "disable": 'netsh advfirewall set publicprofile firewallpolicy allowinbound,allowoutbound',
         "desc": "Harden public profile by blocking unsolicited inbound connections."},
        {"id": "fw_netprot", "name": "Enable Defender Network Protection",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -EnableNetworkProtection Enabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -EnableNetworkProtection Disabled"',
         "desc": "Block known malicious domains at the endpoint."},
        {"id": "fw_disable_smb1", "name": "Disable SMBv1 Protocol",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart"',
         "desc": "Disable legacy SMBv1 unless required by legacy devices."},
        {"id": "fw_disable_llmnr", "name": "Disable LLMNR (DNS alternative)",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v EnableMulticast /f',
         "desc": "Disable LLMNR to prevent local name spoofing attacks."},
    ],
    "Advanced Hardening": [
        {"id": "adv_wpad", "name": "Disable WPAD (Proxy Auto-Discovery)",
         "enable": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad" /v WpadOverride /f',
         "desc": "Disable WPAD to avoid malicious proxy auto-discovery."},
        {"id": "adv_ps2", "name": "Disable PowerShell 2.0 (Downgrade Attack)",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like \'*PowerShellV2*\' } | Disable-WindowsOptionalFeature -Online -NoRestart"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like \'*PowerShellV2*\' } | Enable-WindowsOptionalFeature -Online -All -NoRestart"',
         "desc": "Remove the legacy PowerShell engine to avoid downgrade attacks."},
        {"id": "adv_spooler", "name": "Disable Print Spooler Service",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-Service Spooler -StartupType Automatic; Start-Service Spooler"',
         "desc": "Disable Print Spooler on systems that do not require printing."},
        {"id": "adv_rdp", "name": "Disable Remote Desktop (RDP)",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f',
         "disable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
         "desc": "Disable RDP if remote desktop is not required."},
        {"id": "adv_winrm", "name": "Disable Windows Remote Management (WinRM)",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Stop-Service WinRM -Force; Set-Service WinRM -StartupType Disabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-Service WinRM -StartupType Automatic; Start-Service WinRM"',
         "desc": "Disable WinRM when remote management is not needed."},
        {"id": "adv_dmaguard", "name": "Block DMA Devices when Locked",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DMAGuard" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DMAGuard" /v DeviceEnumerationPolicy /f',
         "desc": "Prevent DMA-based attacks via Thunderbolt/PCIe when locked."},
    ],
    "Additional Hardening": [
        {"id": "add_wsh_disable", "name": "Disable Windows Script Host (system-wide)",
         "enable": 'reg add "HKLM\\Software\\Microsoft\\Windows Script Host\\Settings" /v Enabled /t REG_DWORD /d 0 /f',
         "disable": 'reg add "HKLM\\Software\\Microsoft\\Windows Script Host\\Settings" /v Enabled /t REG_DWORD /d 1 /f',
         "desc": "Disable WSH to prevent .vbs/.js execution via the engine."},
        {"id": "add_autorun_disable", "name": "Disable Autorun / Autoplay for drives",
         "enable": 'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f',
         "disable": 'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /f',
         "desc": "Turn off autorun to reduce USB-based malware spread."},
        {"id": "add_remoteassist_disable", "name": "Disable Remote Assistance",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f',
         "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" /v fAllowToGetHelp /f',
         "desc": "Disable unsolicited remote assistance sessions."},
        {"id": "add_wer_disable", "name": "Disable Windows Error Reporting (prevent auto data send)",
         "enable": 'reg add "HKLM\\Software\\Microsoft\\Windows\\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\Software\\Microsoft\\Windows\\Windows Error Reporting" /v Disabled /f',
         "desc": "Stop automated error reports from sending potentially sensitive details."},
        {"id": "add_chrome_exploit", "name": "Enable Exploit Protection for Chrome (app-specific)",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-ProcessMitigation -Name chrome.exe -Enable DEP,BottomUp,SEHOP,TerminateOnError"',
         "disable": '',
         "desc": "Apply exploit mitigations to Chrome (may not be supported on all systems)."},
        {"id": "add_disable_tips", "name": "Disable Windows Tips & consumer features",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent" /v DisableSoftLanding /f',
         "desc": "Hide consumer tips and soft-landing promotions."},
        {"id": "add_feedback_disable", "name": "Disable Feedback & telemetry prompts",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v DoNotShowFeedbackNotifications /f',
         "desc": "Reduce intrusive feedback & telemetry prompts."},
        {"id": "add_smb_client_fallback", "name": "Disable insecure SMB client fallback",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f',
         "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v AllowInsecureGuestAuth /f',
         "desc": "Prevent insecure guest authentication fallback in SMB client."},
        {"id": "add_webdav_disable", "name": "Disable WebDAV (WebClient service)",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Stop-Service WebClient -Force; Set-Service WebClient -StartupType Disabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-Service WebClient -StartupType Manual; Start-Service WebClient"',
         "desc": "Disable WebClient to reduce WebDAV attack surface."},
        {"id": "add_printpdf_disable", "name": "Disable Print to PDF vulnerability surface",
         "enable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Printers\\Providers" /v DisablePrintToPDF /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Printers\\Providers" /v DisablePrintToPDF /f',
         "desc": "Optional: disable additional printer provider surfaces."},
        {"id": "add_ntlm_block", "name": "Block legacy NTLM authentication (where safe)",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f',
         "disable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 3 /f',
         "desc": "Enforce stronger authentication; test compatibility first."},
        {"id": "add_tls_disable_old", "name": "Disable insecure TLS versions (1.0 / 1.1)",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" /v Enabled /t REG_DWORD /d 0 /f',
         "disable": '',
         "desc": "Disable old TLS versions; ensure application compatibility before enabling."},
        {"id": "add_smartscreen_system", "name": "Enable SmartScreen for Windows (system)",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v EnableSmartScreen /f',
         "desc": "Enable system-level SmartScreen protections."},
        {"id": "add_clipboard_history_disable", "name": "Disable Clipboard History",
         "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f',
         "disable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 1 /f',
         "desc": "Disable storing clipboard history to reduce data leakage."},
        {"id": "add_suggestapps_disable", "name": "Disable Suggested Apps",
         "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent" /v DisableWindowsConsumerFeatures /f',
         "desc": "Prevent Windows from suggesting consumer apps."},
        {"id": "add_peoplebar_disable", "name": "Disable People Bar",
         "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v PeopleBand /t REG_DWORD /d 0 /f',
         "disable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v PeopleBand /t REG_DWORD /d 1 /f',
         "desc": "Remove People quick-access UI element."},
        {"id": "add_fax_disable", "name": "Disable Unnecessary Fax Service",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Stop-Service Fax -Force; Set-Service Fax -StartupType Disabled"',
         "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-Service Fax -StartupType Manual; Start-Service Fax"',
         "desc": "Disable Fax service if not used."},
        {"id": "add_xbox_disable", "name": "Disable Xbox services (telemetry-heavy)",
         "enable": 'powershell -ExecutionPolicy Bypass -Command "Get-Service *xbox* | Stop-Service -Force; Get-Service *xbox* | Set-Service -StartupType Disabled"',
         "disable": '',
         "desc": "Optional: disable Xbox/telemetry services."},
        {"id": "add_wifisense_disable", "name": "Disable WiFi Sense",
         "enable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f',
         "disable": 'reg delete "HKLM\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config" /v AutoConnectAllowedOEM /f',
         "desc": "Disable older WiFi Sense auto-connect features."},
        {"id": "add_remoteshell_disable", "name": "Disable Remote Shell",
         "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinRM\\Service" /v AllowRemoteShellAccess /t REG_DWORD /d 0 /f',
         "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinRM\\Service" /v AllowRemoteShellAccess /f',
         "desc": "Block remote shell access via WinRM if not needed."},
    ],
}

# ------------------------- Recommended Preset -------------------------
# A safe baseline of setting IDs to enable
RECOMMENDED_PRESET = {
    "enable": [
        # File association safe defaults
        "hta_notepad", "wsh_notepad", "wsf_notepad", "bat_notepad", "js_notepad", "jse_notepad", "vbe_notepad", "vbs_notepad",
        # Defender
        "def_pua", "def_maps", "def_elam",
        # ASR
        "asr_office_childproc", "asr_office_inject", "asr_obfuscated_scripts", "asr_script_launch_exec",
        # System protections
        "sys_exploit_prot", "sys_lsass_ppl", "sys_wdigest", "sys_safedll", "sys_uac", "sys_uac_always",
        # Browser & Office
        "br_edge_smartscreen", "br_chrome_siteisolation", "br_chrome_doh", "off_disable_macros",
        # Logging & privacy
        "priv_pslog", "priv_audit_cmdline", "priv_telemetry", "priv_bing", "priv_cortana",
        # Firewall & network
        "fw_all_on", "fw_netprot", "fw_disable_smb1", "fw_disable_llmnr",
        # Advanced (selective)
        "adv_ps2", "adv_dmaguard",
        # Additional safe hardening
        "add_wsh_disable", "add_autorun_disable", "add_clipboard_history_disable", "add_smartscreen_system",
    ],
    "disable": []  # unused today
}

# ------------------------- UI TOOLTIP HELPER -------------------------
class Tooltip:
    """Lightweight tooltip for Tk widgets."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self._enter)
        widget.bind("<Leave>", self._leave)
        widget.bind("<ButtonPress>", self._leave)

    def _enter(self, event=None):
        if self.tipwindow or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 1
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT, background="#ffffe0", relief=tk.SOLID, borderwidth=1, wraplength=360)
        label.pack(ipadx=4, ipady=2)

    def _leave(self, event=None):
        if self.tipwindow:
            try:
                self.tipwindow.destroy()
            except Exception:
                pass
            self.tipwindow = None

# ------------------------- HARDENING TOOL CLASS -------------------------
class HardeningTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Metapod Hardening — Sidebar UI")
        self.root.geometry("1000x720")

        self.log_queue = Queue()
        self.backup_before_changes = tk.BooleanVar(value=True)
        self.vars = {}  # map setting id -> tk.BooleanVar
        self.last_backup_dir = None

        # Top frame controls
        top_frame = ttk.Frame(root, padding=8)
        top_frame.pack(side=tk.TOP, fill=tk.X)

        # Keep a reference to Apply button so we can enable/disable it
        self.apply_button = ttk.Button(top_frame, text="Apply Changes", command=self.start_apply_thread, style="Accent.TButton")
        self.apply_button.pack(side=tk.RIGHT, padx=6)

        ttk.Checkbutton(top_frame, text="Create registry backup + restore point before changes", variable=self.backup_before_changes).pack(side=tk.RIGHT, padx=8)
        ttk.Button(top_frame, text="Select Recommended Preset", command=self.apply_recommended_preset).pack(side=tk.LEFT, padx=6)
        ttk.Button(top_frame, text="Select All", command=self.select_all).pack(side=tk.LEFT, padx=6)
        ttk.Button(top_frame, text="Deselect All", command=self.deselect_all).pack(side=tk.LEFT, padx=6)

        self.root.style = ttk.Style(self.root)
        try:
            self.root.style.configure("Accent.TButton", foreground="black", background="#0f62fe")
        except Exception:
            pass  # styling not critical

        # Main panes: left sidebar for categories, right content
        main_pane = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
        main_pane.pack(expand=True, fill=tk.BOTH, padx=8, pady=(0,8))

        # Left: categories list
        left_frame = ttk.Frame(main_pane, width=220)
        main_pane.add(left_frame, weight=1)

        lbl = ttk.Label(left_frame, text="Categories", font=(None, 11, 'bold'))
        lbl.pack(anchor='w', padx=8, pady=(6,2))

        self.cat_listbox = tk.Listbox(left_frame, exportselection=False, activestyle='none')
        self.cat_listbox.pack(expand=True, fill=tk.BOTH, padx=8, pady=4)
        self.cat_listbox.bind('<<ListboxSelect>>', self.on_category_select)

        for cat in SETTINGS.keys():
            self.cat_listbox.insert(tk.END, cat)
        self.cat_listbox.selection_set(0)

        # Right: content area with options for selected category
        right_frame = ttk.Frame(main_pane)
        main_pane.add(right_frame, weight=4)

        # Top area: category title
        self.cat_title = ttk.Label(right_frame, text='', font=(None, 12, 'bold'))
        self.cat_title.pack(anchor='w', padx=6, pady=(6,0))

        # Scrollable frame for checkboxes
        options_container = ttk.Frame(right_frame)
        options_container.pack(expand=True, fill=tk.BOTH, padx=6, pady=6)

        self.canvas = tk.Canvas(options_container)
        self.canvas.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        scrollbar = ttk.Scrollbar(options_container, orient=tk.VERTICAL, command=self.canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.options_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0,0), window=self.options_frame, anchor='nw')
        self.options_frame.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))

        # Bottom area: log + rollback buttons
        bottom_frame = ttk.Frame(root)
        bottom_frame.pack(fill=tk.BOTH, padx=8, pady=(0,8), expand=False)

        log_frame = ttk.LabelFrame(bottom_frame, text="Output Log")
        log_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=6, pady=4)
        self.output_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=12, state='disabled')
        self.output_log.pack(expand=True, fill=tk.BOTH)

        right_control_frame = ttk.Frame(bottom_frame)
        right_control_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=6)

        ttk.Button(right_control_frame, text="Open Last Backup Folder", command=self.open_last_backup).pack(fill=tk.X, pady=4)
        ttk.Button(right_control_frame, text="Create Rollback Script", command=self.create_rollback_script_ui).pack(fill=tk.X, pady=4)

        # Build variables for each setting
        for cat, items in SETTINGS.items():
            for s in items:
                self.vars[s['id']] = tk.BooleanVar(value=True)

        # Keep the mapping of widgets for tooltips
        self.checkbox_widgets = {}

        # Initially populate the first category
        first_cat = list(SETTINGS.keys())[0] if SETTINGS else None
        if first_cat:
            self.populate_category(first_cat)

        # Start log queue processing
        self.process_log_queue()

    # ------------------------- UI population -------------------------
    def populate_category(self, category_name):
        # Clear existing widgets
        for child in self.options_frame.winfo_children():
            child.destroy()
        self.cat_title.config(text=category_name)

        items = SETTINGS.get(category_name, [])
        for s in items:
            frame = ttk.Frame(self.options_frame)
            frame.pack(fill=tk.X, pady=2, padx=2)

            chk = ttk.Checkbutton(frame, text=s['name'], variable=self.vars[s['id']])
            chk.pack(side=tk.LEFT, anchor='w')
            Tooltip(chk, s.get('desc', ''))

            # info button shows full description in a dialog
            def make_info(desc, title=s['name']):
                return lambda: messagebox.showinfo(title, desc)

            info_btn = ttk.Button(frame, text='i', width=2, command=make_info(s.get('desc', '')))
            info_btn.pack(side=tk.RIGHT, padx=6)

            self.checkbox_widgets[s['id']] = chk

    def on_category_select(self, event=None):
        sel = self.cat_listbox.curselection()
        if not sel:
            return
        cat = self.cat_listbox.get(sel[0])
        self.populate_category(cat)

    # ------------------------- Logging & queue -------------------------
    def process_log_queue(self):
        try:
            while not self.log_queue.empty():
                message = self.log_queue.get_nowait()
                if message == 'TASK_COMPLETE':
                    self.apply_button.config(state='normal')
                    messagebox.showinfo('Finished', 'All selected operations have been completed.')
                else:
                    self.output_log.config(state='normal')
                    self.output_log.insert(tk.END, message + "\n")
                    self.output_log.see(tk.END)
                    self.output_log.config(state='disabled')
        finally:
            self.root.after(150, self.process_log_queue)

    # ------------------------- command execution -------------------------
    def run_command(self, command, name, timeout=120):
        if not command:
            self.log_queue.put(f"[!] Skipped (no command): {name}")
            self.log_queue.put("-" * 40)
            return
        self.log_queue.put(f"[*] Running: {name}")
        try:
            proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            stdout, stderr = proc.communicate(timeout=timeout)
            if stdout:
                self.log_queue.put(f"    Output: {stdout.strip()}")
            if stderr:
                self.log_queue.put(f"    Error: {stderr.strip()}")
            if proc.returncode == 0:
                self.log_queue.put(f"[+] Success: {name}")
            else:
                self.log_queue.put(f"[-] Command finished with code {proc.returncode}: {name}")
        except subprocess.TimeoutExpired:
            self.log_queue.put(f"    Error: Command timed out after {timeout} seconds and was killed.")
            try:
                proc.kill()
                proc.communicate()
            except Exception:
                pass
        except Exception as e:
            self.log_queue.put(f"[!] Exception occurred: {e}")
        self.log_queue.put("-" * 40)

    # ------------------------- apply workflow -------------------------
    def start_apply_thread(self):
        if not messagebox.askyesno('Confirm Changes', 'Are you sure you want to apply the selected changes to your system?'):
            return
        # disable apply button
        self.apply_button.config(state='disabled')
        # Clear log
        self.output_log.config(state='normal')
        self.output_log.delete('1.0', tk.END)
        self.output_log.config(state='disabled')

        thread = threading.Thread(target=self.apply_settings_worker, daemon=True)
        thread.start()

    def apply_settings_worker(self):
        self.log_queue.put('Starting to apply settings...')
        # Safety steps
        if self.backup_before_changes.get():
            try:
                self.log_queue.put('[!] Safety option enabled: registry backup + restore point will be created before changes.')
                backup_dir = self.backup_registry()
                self.last_backup_dir = backup_dir
                self.create_restore_point()
                self.log_queue.put('[+] Safety steps completed. Proceeding to apply changes...')
            except Exception as e:
                self.log_queue.put(f"[!] Failed safety steps: {e}")
        # Apply each setting in order of categories
        for cat, items in SETTINGS.items():
            for s in items:
                var = self.vars.get(s['id'])
                if var and var.get():
                    self.run_command(s.get('enable', ''), f"Enable {s['name']}")
                else:
                    # run disable if present
                    self.run_command(s.get('disable', ''), f"Disable {s['name']}")
        self.log_queue.put('All tasks completed.')
        self.log_queue.put('TASK_COMPLETE')

    # ------------------------- selection helpers -------------------------
    def select_all(self):
        for k in self.vars:
            self.vars[k].set(True)
        # refresh displayed category
        sel = self.cat_listbox.curselection()
        if sel:
            self.populate_category(self.cat_listbox.get(sel[0]))

    def deselect_all(self):
        for k in self.vars:
            self.vars[k].set(False)
        sel = self.cat_listbox.curselection()
        if sel:
            self.populate_category(self.cat_listbox.get(sel[0]))

    def apply_recommended_preset(self):
        if not messagebox.askyesno('Apply Recommended Preset', 'Apply the recommended safe baseline preset?\nThis will set selections but will NOT apply changes.'):
            return
        # deselect all first
        for k in self.vars:
            self.vars[k].set(False)
        for sid in RECOMMENDED_PRESET.get('enable', []):
            if sid in self.vars:
                self.vars[sid].set(True)
        # refresh view
        sel = self.cat_listbox.curselection()
        if sel:
            self.populate_category(self.cat_listbox.get(sel[0]))
        self.log_queue.put('[+] Recommended preset applied to selections (not executed).')

    # ------------------------- safety helpers -------------------------
    def backup_registry(self):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = os.path.join(os.getcwd(), f'RegistryBackup_{ts}')
        os.makedirs(backup_dir, exist_ok=True)
        self.log_queue.put(f"[*] Creating registry backup in: {backup_dir}")
        exports = [
            (r'HKLM', os.path.join(backup_dir, 'HKLM.reg')),
            (r'HKCU', os.path.join(backup_dir, 'HKCU.reg')),
            (r'HKCR', os.path.join(backup_dir, 'HKCR.reg')),
            (r'HKU', os.path.join(backup_dir, 'HKU.reg')),
        ]
        for hive, path in exports:
            cmd = f'reg export "{hive}" "{path}" /y'
            self.run_command(cmd, f"Export {hive} to {os.path.basename(path)}", timeout=180)
        meta_path = os.path.join(backup_dir, 'metadata.txt')
        try:
            with open(meta_path, 'w', encoding='utf-8') as f:
                f.write(f"Created: {datetime.datetime.now().isoformat()}\n")
                f.write("Tool: metapod_hardening_final.py\n")
            self.log_queue.put(f"[+] Registry backup created: {backup_dir}")
        except Exception as e:
            self.log_queue.put(f"[!] Error writing metadata: {e}")
        return backup_dir

    def create_restore_point(self):
        self.log_queue.put('[*] Creating System Restore Point (requires System Protection enabled)...')
        cmd = (
            'powershell -ExecutionPolicy Bypass -Command '
            '"if (Get-ComputerRestorePoint -ErrorAction SilentlyContinue) { Checkpoint-Computer -Description \\"Metapod Hardening Restore Point\\" -RestorePointType \\"MODIFY_SETTINGS\\" } else { Write-Host \\"System Restore is unavailable or disabled.\\"; exit 2 }"'
        )
        self.run_command(cmd, 'Create System Restore Point', timeout=180)

    # ------------------------- backup / rollback utilities -------------------------
    def open_last_backup(self):
        if not self.last_backup_dir or not os.path.isdir(self.last_backup_dir):
            messagebox.showinfo('No Backup', 'No backup has been created yet during this session.')
            return
        try:
            subprocess.Popen(f'explorer "{self.last_backup_dir}"')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to open folder: {e}')

    def create_rollback_script_ui(self):
        if not self.last_backup_dir or not os.path.isdir(self.last_backup_dir):
            messagebox.showinfo('No Backup', 'No backup has been created yet during this session.\nRun a backup by enabling the safety option and clicking Apply.')
            return
        proceed = messagebox.askyesno('Create Rollback Script',
                                      f'Create a rollback script that will import registry backups from:\n{self.last_backup_dir}\n\nThis script will import registry .reg files when run as Administrator. Continue?')
        if not proceed:
            return
        try:
            script_path = self.create_rollback_script(self.last_backup_dir)
            messagebox.showinfo('Rollback Created', f'Rollback script created: {script_path}\nRun it as Administrator to import registry backups.')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to create rollback script: {e}')

    def create_rollback_script(self, backup_dir):
        script_path = os.path.join(backup_dir, 'rollback_restore_registry.bat')
        lines = [
            '@echo off\n',
            ':: Rollback script generated by metapod_hardening_final.py\n',
            ':: Run this script as Administrator to import the exported registry hives.\n',
            'echo Importing registry backups...\n',
        ]
        for name in ('HKLM.reg', 'HKCU.reg', 'HKCR.reg', 'HKU.reg'):
            path = os.path.join(backup_dir, name)
            if os.path.isfile(path):
                lines.append(f'echo Importing {name}...\n')
                lines.append(f'reg import "{path}"\n')
                lines.append('if %errorlevel% neq 0 echo Warning: import failed for {0} & pause\n'.format(name))
        lines.append('echo Done. It is recommended to restart the computer.\n')
        lines.append('pause\n')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

        # PowerShell variant
        ps_path = os.path.join(backup_dir, 'rollback_restore_registry.ps1')
        ps_lines = ['Write-Host "Importing registry backups..."\n']
        for name in ('HKLM.reg', 'HKCU.reg', 'HKCR.reg', 'HKU.reg'):
            path = os.path.join(backup_dir, name)
            if os.path.isfile(path):
                ps_lines.append(f'Write-Host "Importing {name}..."\n')
                ps_lines.append(f'try {{ reg import "{path}" }} catch {{ Write-Warning "Import failed for {name}: $_" }}\n')
        ps_lines.append('Write-Host "Done. Restart recommended."\n')
        with open(ps_path, 'w', encoding='utf-8') as f:
            f.writelines(ps_lines)

        self.log_queue.put(f"[+] Rollback scripts created in {backup_dir}")
        return script_path

# ------------------------- Helper: elevation check & re-run -------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# ------------------------- Main -------------------------
if __name__ == '__main__':
    if is_admin():
        root = tk.Tk()
        app = HardeningTool(root)
        root.mainloop()
    else:
        script_path = os.path.abspath(sys.argv[0])
        params = f'"{script_path}"'
        try:
            ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, params, None, 1)
        except Exception as e:
            # fallback: show a message box if tkinter is available
            try:
                messagebox.showerror('Elevation Required', f'This tool requires Administrator privileges. Failed to elevate: {e}')
            except Exception:
                print(f'This tool requires Administrator privileges. Failed to elevate: {e}')
