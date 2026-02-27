# 🛡️ Thick-Client VAPT Automation Toolkit

A **PowerShell-based assessment framework** designed to help security teams evaluate Windows thick-client applications safely, consistently, and without intrusive actions.

The toolkit performs **23 read-only security checks**, covering:

- Binaries
- DLL behavior
- Filesystem permissions
- Registry hygiene
- Configuration exposure
- Cryptography usage
- Runtime process analysis

---

## 🔍 Overview

Thick-client applications often combine:

- Local executables  
- Configuration files  
- Registry entries  
- Dynamic runtime behavior  

This creates a wide attack surface where misconfigurations can lead to:

- Privilege escalation  
- Credential leakage  
- Insecure storage  
- DLL hijacking  

This toolkit automates the discovery of such weaknesses by performing **static and runtime analysis without modifying the system or the application**.

It is designed for:

- Internal security assessments  
- Pre-deployment reviews  
- Vendor application evaluations  
- Compliance audits  
- Thick-client hardening exercises  

✅ All checks are **read-only**, making the toolkit safe for authorized production environments.

---

## ⚙️ How the Toolkit Works

The script runs a sequence of **23 independent test cases**. Each test case focuses on a specific attack surface:

- Binary inspection (signatures, strings, weak crypto)
- Filesystem ACL analysis (writable directories, hijack vectors)
- Configuration & secrets scanning (config files, logs, extended formats)
- Registry discovery & ACL checks
- Process-level DLL enumeration
- DLL injection exposure analysis (safe, non-intrusive)
- Service path validation
- Local database discovery
- Insecure protocol and TLS bypass detection

Results are written to a structured output folder for easy review and reporting.

---

## 📁 Output Structure

All results are stored under:
VAPT_TEST/

Each file corresponds to a specific test case, such as:

- `dll_list.txt` — Inventory of all DLL/EXE files  
- `SignatureReport.csv` — Authenticode signature validation  
- `InterestingStrings.txt` — Filtered sensitive strings  
- `WeakCrypto.txt` — MD5/SHA1/DES/RC4 usage  
- `WritableSubdirectories.txt` — DLL hijack indicators  
- `RegistryPermissions.txt` — Weak registry ACLs  
- `LoadedDLLs.txt` — DLLs loaded by selected process  
- `DllInjectionExposure.txt` — Safe DLL injection exposure analysis  
- `VulnerabilitySummary.txt` — Consolidated findings  

This structure makes it easy to:

- Archive results  
- Compare assessments  
- Integrate into audit workflows  

---

## 🧪 The 23 Test Cases

The toolkit currently performs:

1. DLL/EXE inventory  
2. Signature validation  
3. Raw string extraction  
4. Sensitive string filtering  
5. Folder ACL analysis  
6. Automated registry discovery  
7. Weak crypto detection  
8. Config sensitive data scan  
9. Log sensitive data scan  
10. DLL load enumeration  
11. Writable subdirectories  
12. Extended config secret scan  
13. Insecure protocol usage  
14. Embedded private key detection  
15. Connection string detection  
16. Debug/verbose mode detection  
17. Temp/AppData usage scan  
18. Unquoted service path detection  
19. Weak executable permissions  
20. Advanced secrets (API keys, JWTs, cloud keys)  
21. Local database discovery  
22. Insecure HTTP/TLS bypass patterns  
23. DLL Injection Exposure Analysis (safe, read-only)  

Each test case is independent and contributes to the final summary.

---

## 🚀 How to Run the Toolkit

### 1️⃣ Place the script inside the application directory

Example:
```
cd C:\Program Files\YourApp\
```
---

### 2️⃣ Open PowerShell

Running as **Administrator** is recommended for registry and service checks and run PowerShell Execution Policy Bypass.
```
powershell -ep bypass
```

---

### 3️⃣ Execute the script
```
.\Thickclient-Test.ps1
```
---

### 4️⃣ Follow prompts

- Select a process (index or PID) for DLL enumeration  
- Provide an application name for registry discovery (optional)  

---

### 5️⃣ Review results

All findings will be inside:
VAPT_TEST/

The most important file is:
VAPT_TEST\VulnerabilitySummary.txt

---

## ⚠️ Limitations

This toolkit is intentionally **non-intrusive**.

### ❌ Not Performed

- No DLL injection  
- No memory manipulation  
- No privilege escalation attempts  
- No patching or tampering  
- No brute-forcing or fuzzing  
- No network traffic interception  

### 🔒 Protected Processes

Some processes (e.g., VeraCrypt, antivirus, system processes) cannot be enumerated due to Windows protections. DLL-related tests will skip these safely.

### ▶ Requires a Running Instance

DLL enumeration and injection-exposure analysis require the target application to be running.

---

## 📥 Download the Script

Click the link below to download the latest version of **Thickclient-Test.ps1**:

👉 *[https://github.com/Shankar01081991/Thick-Client-VAPT-Automation-Toolkit.md/blob/main/Thickclient-Test.ps1]*  

> Ensure your environment allows downloading `.ps1` files.  
> If not, right-click → **Save As**.

---

## 📌 Notes

- Designed for **authorized security testing only**
- Read-only by design
- Safe for structured enterprise assessments
- Suitable for audit documentation and compliance workflows

---
POC:
---

<img width="832" height="1126" alt="image" src="https://github.com/user-attachments/assets/394b52cd-cb25-476a-9652-0ac97ade6394" />
---

