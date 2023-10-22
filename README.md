# Изучение механизма нападения в соответствии с правилами open-xp-rules.

## mitre_attck_comm_and_ctrl

- [Правило IIS_RDP_or_SMB_Tunneling](/mitre_attck_comm_and_ctrl/IIS_RDP_or_SMB_Tunneling.md)
- [Правило RDP_Tunneling](/mitre_attck_comm_and_ctrl/RDP_Tunneling.md)
- [Правило RDP_Tunneling_via_SSH_5156](/mitre_attck_comm_and_ctrl/RDP_Tunneling_via_SSH_5156.md)

## mitre_attck_cred_access

- [Правило An_attempt_was_made_to_lsass_process](/mitre_attck_cred_access/An_attempt_was_made_to_lsass_process.md)
- [Правило Chrome_firefox_opera_cred_read](/mitre_attck_cred_access/Chrome_firefox_opera_cred_read.md)
- [Правило Credentials_MiniDumpWriteDump_Lsass](/mitre_attck_cred_access/Credentials_MiniDumpWriteDump_Lsass.md)
- [Правило DCSync](/mitre_attck_cred_access/DCSync.md)
- [Правило Dump_lsass_via_process_access:](/mitre_attck_cred_access/Dump_lsass_via_process_access.md)
- [Правило KeePass_CredDump](/mitre_attck_cred_access/KeePass_CredDump.md)
- [Правило Keepass_Key_Dump_Via_KeeThief](/mitre_attck_cred_access/Keepass_Key_Dump_Via_KeeThief.md)
- [Правило Kerberos_pwd_spraying](/mitre_attck_cred_access/Kerberos_pwd_spraying.md)
- [Правило LSASS_ProcDump](/mitre_attck_cred_access/LSASS_ProcDump.md)
- [Правило Mimikatz](/mitre_attck_cred_access/Mimikatz.md)
- [Правило Mimikatz_Memssp_Default_Log_Detected](/mitre_attck_cred_access/Mimikatz_Memssp_Default_Log_Detected.md)
- [Правило PPL_Bypass_via_PPLDump_Tool](/mitre_attck_cred_access/PPL_Bypass_via_PPLDump_Tool.md)
- [Правило Phishing_windows_credentials_powershell_scriptblock](/mitre_attck_cred_access/Phishing_windows_credentials_powershell_scriptblock.md)
- [Правило Remote_registry_access](/mitre_attck_cred_access/Remote_registry_access.md)

## mitre_attck_defense_evasion

- [Change_powershell_policy_registry](/mitre_attck_defense_evasion/Change_powershell_policy_registry.md)
- [Clearing_eventlog](/mitre_attck_defense_evasion/Clearing_eventlog.md)
- [DCShadow_Attack](/mitre_attck_defense_evasion/DCShadow_Attack.md)
- [Detect_Fake_ComputerAccount](/mitre_attck_defense_evasion/Detect_Fake_ComputerAccount.md)
- [Detect_hiding_files_via_attrib_cmdlet](/mitre_attck_defense_evasion/Detect_hiding_files_via_attrib_cmdlet.md)
- [Detect_lolbin_pcalua_exec](/mitre_attck_defense_evasion/Detect_lolbin_pcalua_exec.md)
- [ImageLoad_from_Network_Share_to_LSASS](/mitre_attck_defense_evasion/ImageLoad_from_Network_Share_to_LSASS.md)
- [Правило ParentPid_Spoofing](/mitre_attck_defense_evasion/ParentPid_Spoofing.md)
- [Правило Portproxy_netsh](/mitre_attck_defense_evasion/Portproxy_netsh.md)
- [Правило RDP_settings_tampering](/mitre_attck_defense_evasion/RDP_settings_tampering.md)
- [Правило ReverseShell_created_via_PEInjection](/mitre_attck_defense_evasion/ReverseShell_created_via_PEInjection.md)
- [Правило Subrule_ParentPid_Spoofing](/mitre_attck_defense_evasion/Subrule_ParentPid_Spoofing.md)
- [Правило Suspend_prpcess](/mitre_attck_defense_evasion/Suspend_Process.md)
- [Правило Suspicious_Explorer_Injection](/mitre_attck_defense_evasion/Suspicious_Explorer_Injection.md)

## mitre_attck_discovery
- [Правило Bloodhound](/mitre_attck_discovery/Bloodhound.md)
- [Правило Enumeration_Users_In_Groups](/mitre_attck_discovery/Enumeration_Users_In_Groups.md)
- [Правило Local_Groups_Enumeration_Discovery](/mitre_attck_discovery/Local_Groups_Enumeration_Discovery.md)

## mitre_attck_execution
- [Правило Detect_execution_imageload_wuauclt_lolbas](/mitre_attck_execution/Detect_execution_imageload_wuauclt_lolbas.md)
- [Правило Schtasks_Commandline](/mitre_attck_execution/Schtasks_Commandline.md)
- [Правило Start_process_as_vshadow_child](/mitre_attck_execution/Start_process_as_vshadow_child.md)
- [Правило VSSVC_service_state_changed](/mitre_attck_execution/VSSVC_service_state_changed.md)
- [Правило XP_Cmdshell_Usage](/mitre_attck_execution/XP_Cmdshell_Usage.md)

## mitre_attck_initial_access
- [Правило ProxyNotShell](/mitre_attck_initial_access/ProxyNotShell.md)

## mitre_attck_lat_move
- [Правило Detect_MSHTA_LethalHTA](/mitre_attck_lat_move/Detect_MSHTA_LethalHTA.md)
- [Правило Impacket_WMIExec_Command_Executed](/mitre_attck_lat_move/Impacket_WMIExec_Command_Executed.md)

## mitre_attck_persist
- [Правило Change_wmi_subscription](/mitre_attck_persist/Change_wmi_subscription.md)
- [Правило Create_hidden_local_account](/mitre_attck_persist/Create_hidden_local_account.md)
- [Правило Create_persist_via_Hidden_Run_key_value](/mitre_attck_persist/Create_persist_via_Hidden_Run_key_value.md)
- [Правило Create_persist_via_WinlogonShell](/mitre_attck_persist/Create_persist_via_WinlogonShell.md)
- [Правило DCSync_prepare_Add_replicatation_rights_to_Account](/mitre_attck_persist/DCSync_prepare_Add_replicatation_rights_to_Account.md)
- [Правило DSRM_Password_Changed](/mitre_attck_persist/DSRM_Password_Changed.md)
- [Правило Use_persist_Start_process_via_WinlogonShell](/mitre_attck_persist/Use_persist_Start_process_via_WinlogonShell.md)
- [Правило XP_Cmdshell_Enable](/mitre_attck_persist/XP_Cmdshell_Enable.md)

## mitre_attck_priv_esc
- [Правило CreateProcessAsUser_Impersonation](/mitre_attck_priv_esc/CreateProcessAsUser_Impersonation.md)
- [Правило Detect_Pass_the_Hash_via_Mimikatz_local](/mitre_attck_priv_esc/Detect_Pass_the_Hash_via_Mimikatz_local.md)
- [Правило Named_Pipe_Impersonation_PrivEsc](/mitre_attck_priv_esc/Named_Pipe_Impersonation_PrivEsc.md)
- [Правило Potential_Privileged_Escalation_via_KrbRelayUp](/mitre_attck_priv_esc/Potential_Privileged_Escalation_via_KrbRelayUp.md)
- [Правило SeDebugPrivilege_Enabled](/mitre_attck_priv_esc/SeDebugPrivilege_Enabled.md)
- [Правило UACME_23_DismCore_Hijacking](/mitre_attck_priv_esc/UACME_23_DismCore_Hijacking.md)
- [Правило UAC_Bypass_Via_Consent](/mitre_attck_priv_esc/UAC_Bypass_Via_Consent.md)
- [Правило Unquoted_Service_Path_Abuse](/mitre_attck_priv_esc/Unquoted_Service_Path_Abuse.md)
- [Правило sAMAccountName_Spoofing](/mitre_attck_priv_esc/sAMAccountName_Spoofing.md)