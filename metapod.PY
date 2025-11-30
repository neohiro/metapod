import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import ctypes
import sys
import threading
from queue import Queue
import os

# Data structure containing all settings, categorized for the GUI tabs.
# PowerShell commands are now more robust with ExecutionPolicy Bypass.
# UPDATED: PowerShell 2.0 commands now use a 'Find and Disable' logic to prevent 'Feature Unknown' errors.
SETTINGS = {
    "File Associations": [
        {"name": "Harden .hta files (open in Notepad)", "enable": 'ftype htafile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"', "disable": 'ftype htafile="%SystemRoot%\\System32\\mshta.exe" "%1" %*'},
        {"name": "Harden .wsh files (open in Notepad)", "enable": 'ftype wshfile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"', "disable": 'ftype wshfile="%SystemRoot%\\System32\\WScript.exe" "%1" %*'},
        {"name": "Harden .wsf files (open in Notepad)", "enable": 'ftype wsffile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"', "disable": 'ftype wsffile="%SystemRoot%\\System32\\WScript.exe" "%1" %*'},
        {"name": "Harden .bat files (open in Notepad)", "enable": 'ftype batfile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"', "disable": 'ftype batfile="%1" %*'},
        {"name": "Harden .js files (open in Notepad)", "enable": 'ftype jsfile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"', "disable": 'ftype jsfile="%SystemRoot%\\System32\\WScript.exe" "%1" %*'},
        {"name": "Harden .jse files (open in Notepad)", "enable": 'ftype jsefile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"', "disable": 'ftype jsefile="%SystemRoot%\\System32\\WScript.exe" "%1" %*'},
        {"name": "Harden .vbe files (open in Notepad)", "enable": 'ftype vbefile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"', "disable": 'ftype vbefile="%SystemRoot%\\System32\\WScript.exe" "%1" %*'},
        {"name": "Harden .vbs files (open in Notepad)", "enable": 'ftype vbsfile="%SystemRoot%\\system32\\NOTEPAD.EXE" "%1"', "disable": 'ftype vbsfile="%SystemRoot%\\System32\\WScript.exe" "%1" %*'},
    ],
    "Windows Defender": [
        {"name": "Enable Windows Defender Sandboxing", "enable": 'setx /M MP_FORCE_USE_SANDBOX 1', "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" /v MP_FORCE_USE_SANDBOX /f'},
        {"name": "Enable PUA (Potentially Unwanted App) Protection", "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -PUAProtection Enable"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -PUAProtection Disable"'},
        {"name": "Enable Defender Periodic Scanning (Passive Mode)", "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f', "disable": 'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows Defender" /v PassiveMode /f'},
        {"name": "Enable Advanced Cloud Protection (MAPS)", "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -MAPSReporting Advanced"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -MAPSReporting 0"'},
        {"name": "Disable Automatic Sample Submission", "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -SubmitSamplesConsent 0"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -SubmitSamplesConsent 1"'},
        {"name": "Enable Early Launch Anti-Malware (ELAM)", "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f', "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch" /v DriverLoadPolicy /f'},
    ],
    "Attack Surface Reduction": [
        {"name": "Block Office Child Process Creation", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Office Process Injection", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Office Win32 API Calls", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Office from Creating Executables", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Obfuscated Scripts", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Executable Content from Email", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block JS/VBScript from Launching Executables", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Credential Theft from LSASS", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Untrusted Processes from USB", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Adobe Reader Child Process Creation", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Persistence via WMI Event Subscription", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Disabled"'},
        {"name": "Block Processes from PSExec and WMI", "enable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Disabled"'},
    ],
    "System-Wide Protections": [
        {"name": "Enable System-Wide Exploit Protection (DEP, SEHOP, etc.)", "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-Processmitigation -System -Disable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError"'},
        {"name": "Harden LSASS Against Credential Dumping", "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /f'},
        {"name": "Disable WDigest Credential Caching", "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f', "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /f'},
        {"name": "Enable Safe DLL Search Mode", "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v SafeDLLSearchMode /f'},
        {"name": "Enable UAC (User Account Control)", "enable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f', "disable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 0 /f'},
        {"name": "Set UAC to Always Notify", "enable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f', "disable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f'},
    ],
    "Browser & Office": [
        {"name": "Enable SmartScreen for Edge", "enable": 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f', "disable": 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f'},
        {"name": "Disable Edge Password Manager", "enable": 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f', "disable": 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main" /v "FormSuggest Passwords" /t REG_SZ /d yes /f'},
        {"name": "Chrome: Enable Site Isolation (SitePerProcess)", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "SitePerProcess" /f'},
        {"name": "Chrome: Enable DNS-over-HTTPS", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d "on" /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "DnsOverHttpsMode" /f'},
        {"name": "Chrome: Block External Extensions", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v "BlockExternalExtensions" /f'},
        {"name": "Office: Disable Macros with Notification", "enable": 'reg add "HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security" /v vbawarnings /t REG_DWORD /d 4 /f', "disable": 'reg add "HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security" /v vbawarnings /t REG_DWORD /d 1 /f'},
        {"name": "Office: Block Content Execution from Internet", "enable": 'reg add "HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f', "disable": 'reg add "HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 0 /f'},
        {"name": "Office: Harden against DDE attacks", "enable": 'reg add "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Options" /v DontUpdateLinks /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Options" /v DontUpdateLinks /f'},
    ],
    "Privacy & Logging": [
        {"name": "Set Telemetry to Security Only", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f', "disable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 3 /f'},
        {"name": "Disable Advertising ID", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo" /v DisabledByGroupPolicy /f'},
        {"name": "Disable Location Data", "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" /v Value /t REG_SZ /d Deny /f', "disable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" /v Value /t REG_SZ /d Allow /f'},
        {"name": "Disable Bing Search in Start Menu", "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f', "disable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" /v BingSearchEnabled /t REG_DWORD /d 1 /f'},
        {"name": "Disable Cortana", "enable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" /v CortanaConsent /t REG_DWORD /d 0 /f', "disable": 'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" /v CortanaConsent /t REG_DWORD /d 1 /f'},
        {"name": "Enable PowerShell Script Block Logging", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /f'},
        {"name": "Audit: Include Command Line in Process Creation Events", "enable": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f'},
    ],
    "Firewall & Network": [
        {"name": "Turn on Windows Firewall for All Profiles", "enable": 'NetSh Advfirewall set allprofiles state on', "disable": 'NetSh Advfirewall set allprofiles state off'},
        {"name": "Block All Inbound Connections (Public Profile)", "enable": 'netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound', "disable": 'netsh advfirewall set publicprofile firewallpolicy allowinbound,allowoutbound'},
        {"name": "Enable Defender Network Protection", "enable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -EnableNetworkProtection Enabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-MpPreference -EnableNetworkProtection Disabled"'},
        {"name": "Disable SMBv1 Protocol", "enable": 'powershell -ExecutionPolicy Bypass -Command "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart"'},
        {"name": "Disable NetBIOS over TCP/IP", "enable": 'wmic nicconfig where "TcpipNetbiosOptions is not null" call SetTcpipNetbios 2', "disable": 'wmic nicconfig where "TcpipNetbiosOptions is not null" call SetTcpipNetbios 0'},
        {"name": "Disable LLMNR (DNS alternative)", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v EnableMulticast /f'},
        {"name": "Firewall: Block Notepad network connections", "enable": 'Netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\\system32\\notepad.exe" dir=out action=block', "disable": 'Netsh advfirewall firewall delete rule name="Block Notepad.exe netconns"'},
        {"name": "Firewall: Block Calculator network connections", "enable": 'Netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\\system32\\calc.exe" dir=out action=block', "disable": 'Netsh advfirewall firewall delete rule name="Block calc.exe netconns"'},
    ],
    "Advanced Hardening": [
        {"name": "Disable WPAD (Proxy Auto-Discovery)", "enable": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f', "disable": 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad" /v WpadOverride /f'},
        {"name": "Disable PowerShell 2.0 (Downgrade Attack)", "enable": 'powershell -ExecutionPolicy Bypass -Command "Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like \'*PowerShellV2*\' } | Disable-WindowsOptionalFeature -Online -NoRestart"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like \'*PowerShellV2*\' } | Enable-WindowsOptionalFeature -Online -All -NoRestart"'},
        {"name": "Disable Print Spooler Service", "enable": 'powershell -ExecutionPolicy Bypass -Command "Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-Service Spooler -StartupType Automatic; Start-Service Spooler"'},
        {"name": "Disable Remote Desktop (RDP)", "enable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', "disable": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'},
        {"name": "Disable Windows Remote Management (WinRM)", "enable": 'powershell -ExecutionPolicy Bypass -Command "Stop-Service WinRM -Force; Set-Service WinRM -StartupType Disabled"', "disable": 'powershell -ExecutionPolicy Bypass -Command "Set-Service WinRM -StartupType Automatic; Start-Service WinRM"'},
        {"name": "Disable Windows Timeline (Activity Feed)", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v EnableActivityFeed /f'},
        {"name": "Block DMA Devices when Locked", "enable": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DMAGuard" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f', "disable": 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DMAGuard" /v DeviceEnumerationPolicy /f'},
    ]
}

class HardeningTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows 10 & 11 Hardening Tool")
        self.root.geometry("800x600")
        
        self.vars = []
        self.log_queue = Queue()

        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(expand=True, fill="both")

        # --- Top frame for controls ---
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill="x", pady=5)

        ttk.Button(control_frame, text="Select All", command=self.select_all).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Deselect All", command=self.deselect_all).pack(side="left", padx=5)
        
        self.apply_button = ttk.Button(control_frame, text="Apply Changes", command=self.start_apply_thread, style="Accent.TButton")
        self.apply_button.pack(side="right", padx=5)
        self.root.style = ttk.Style(self.root)
        self.root.style.configure("Accent.TButton", foreground="black", background="blue")

        # --- Notebook for settings ---
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill="both", pady=5)
        
        self.create_settings_tabs()

        # --- Output log ---
        log_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="5")
        log_frame.pack(expand=True, fill="both", pady=5)
        self.output_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, state='disabled')
        self.output_log.pack(expand=True, fill="both")

        # Start the queue processor
        self.process_log_queue()

    def create_settings_tabs(self):
        """Populates the notebook with tabs and checkboxes based on the SETTINGS dictionary."""
        for category, settings_list in SETTINGS.items():
            tab = ttk.Frame(self.notebook, padding="10")
            self.notebook.add(tab, text=category)
            
            for i, setting in enumerate(settings_list):
                var = tk.BooleanVar(value=True) # Default to checked
                chk = ttk.Checkbutton(tab, text=setting["name"], variable=var)
                chk.grid(row=i, column=0, sticky="w", pady=2)
                self.vars.append((var, setting))

    def process_log_queue(self):
        """Processes messages from the log_queue to update the GUI safely."""
        try:
            while not self.log_queue.empty():
                message = self.log_queue.get_nowait()
                if message == "TASK_COMPLETE":
                    self.apply_button.config(state="normal")
                    messagebox.showinfo("Finished", "All selected operations have been completed.")
                else:
                    self.output_log.config(state='normal')
                    self.output_log.insert(tk.END, message + "\n")
                    self.output_log.see(tk.END)
                    self.output_log.config(state='disabled')
        finally:
            self.root.after(100, self.process_log_queue)

    def run_command(self, command, name):
        """Executes a command using Popen for better control and puts its output into the log_queue."""
        self.log_queue.put(f"[*] Running: {name}")
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            # communicate() waits for the process to finish and gets the output.
            # UPDATED: Increased timeout to 60s because scanning features can be slow.
            stdout, stderr = proc.communicate(timeout=60)

            if stdout:
                self.log_queue.put(f"    Output: {stdout.strip()}")
            if stderr:
                self.log_queue.put(f"    Error: {stderr.strip()}")

            if proc.returncode == 0:
                 self.log_queue.put(f"[+] Success: {name}")
            else:
                 self.log_queue.put(f"[-] Command finished with code {proc.returncode}: {name}")
        except subprocess.TimeoutExpired:
            self.log_queue.put(f"    Error: Command timed out after 60 seconds and was killed.")
            proc.kill()  # Ensure the hung process is terminated
            proc.communicate() # Clean up the streams
        except Exception as e:
            self.log_queue.put(f"[!] Exception occurred: {e}")
        self.log_queue.put("-" * 40)


    def start_apply_thread(self):
        """Starts the background thread to apply settings, preventing GUI freeze."""
        if not messagebox.askyesno("Confirm Changes", "Are you sure you want to apply the selected changes to your system?"):
            return
        
        self.apply_button.config(state="disabled")
        
        # Clear the log widget directly before starting
        self.output_log.config(state='normal')
        self.output_log.delete('1.0', tk.END)
        self.output_log.config(state='disabled')

        # Create and start the worker thread
        thread = threading.Thread(target=self.apply_settings_worker, daemon=True)
        thread.start()

    def apply_settings_worker(self):
        """Worker function that runs in a separate thread."""
        self.log_queue.put("Starting to apply settings...")

        for var, setting in self.vars:
            if var.get(): # If checkbox is checked, apply the 'enable' command
                self.run_command(setting["enable"], f"Enable {setting['name']}")
            else: # If unchecked, apply the 'disable' command
                self.run_command(setting["disable"], f"Disable {setting['name']}")
        
        self.log_queue.put("All tasks completed.")
        self.log_queue.put("TASK_COMPLETE") # Signal to the main thread that we are done

    def select_all(self):
        """Checks all checkboxes."""
        for var, _ in self.vars:
            var.set(True)

    def deselect_all(self):
        """Unchecks all checkboxes."""
        for var, _ in self.vars:
            var.set(False)

def is_admin():
    """Checks if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if is_admin():
        root = tk.Tk()
        app = HardeningTool(root)
        root.mainloop()
    else:
        # Re-run the script with admin rights
        # Get the absolute path to the script to handle all execution scenarios
        script_path = os.path.abspath(sys.argv[0])
        # Use ShellExecuteW to request elevation, ensuring the script path is quoted
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)
