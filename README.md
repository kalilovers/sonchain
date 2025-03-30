<h4 align="center" dir="rtl">
  Rumi
  &#x200F;<br>گفتم به نگار من کز جور مرا مشکن     ,     گفتا به صدف مانی کو دُر به شکم دارد
  <br>تا نشکنی ای شیدا آن دُر نشود پیدا     ,      آن دُر بُتِ من باشد یا شکل بُتم دارد
  <br>
</h4>


<br>

<h6 align="center" dir="ltr">
  📖Change the document language :
  <br><a href="/README.md">1️⃣English</a> &nbsp; | &nbsp; <a href="/README-FA.md">2️⃣فارسی</a>
</h6>


<br>


<h1 align="center" dir="ltr">
  🚀Sonchain - A Network-Based Tool
  <br> 
</h1>

<p align="center" dir="ltr">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.2.0-green.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python->=3.7-blue.svg" alt="Python">
</p>

<a id="about"></a>
## <br><br>🕵🏻‍♂️ Overview:
**Sonchain is a script under development that combines powerful wrapper software, internal (currently Tor) or external VPN-proxy tools, and other utilities.
<br>It enables the execution of commands, programs, and more through a proxy, bypassing network restrictions based on IP, DNS, and geographic limitations, while offering even broader capabilities. This tool is designed for seamless communication, security testing, and specialized use.**

<br><br><br>

<a id="Introduction"></a>

<table dir="ltr" width="100%">
<tr>
<td>

**SonChain Version 1.2.0**

## 🔍 Introduction & Features

**SonChain** is a script under development that integrates powerful wrapper software and VPN/Proxy tools (currently Tor), allowing you to execute commands and programs through a proxy and bypass network restrictions based on IP, DNS, geographic location, etc. Below are some key applications and technical details:

<br> ─| **Executing Commands via Proxy:**

Supported commands based on available tools: dnsson - proxyson - proxychains4 - socksify

  <ul dir="ltr" style="text-align: left;">
    <li> <b>dnsson:</b> Temporarily changes the system's DNS settings to Tor proxy DNS so that DNS requests such as <code>dig</code> are sent through the proxy.</li>
    <li> <b>proxyson:</b> In addition to changing DNS, it routes the TCP traffic of your commands through the proxy; this tool internally uses <code>socksify</code> or <code>proxychains4</code> (therefore, one of them must be installed).</li>
    <li> <b>proxychains4 and socksify:</b> These tools are also used to route software and command traffic through a proxy, but direct use of <code>socksify</code> may cause DNS leaks.</li>
  </ul>

<br> ─| **Usage Example:**
**▪️ To use, simply place the "tool invocation command" before the "main command":**  

`proxyson apt update`    
`proxychains4 apt update`  
`dnsson dig example.com`  
`socksify curl example.com`  

`Or install packages from restricted repositories, etc.`

<br> ─| **Example of Using Tor's Dedicated Ports:**
  
  - **Tor Proxy DNS:** You can use the IP and PORT assigned to Tor’s proxy DNS as a nameserver or resolver proxy capable of bypassing various DNS-based restrictions; these settings only overcome DNS-layer limitations.
  - **Tor SOCKS Proxy:** The IP and PORT corresponding to Tor’s SOCKS proxy serve as a secure endpoint for transmitting application traffic, desired traffic, or for other network-related uses.

<br> ─| **Bypassing Network Restrictions at the Server Level or in Specific Sections:**
   - By using Tor’s internal DNS or SOCKS to route traffic or resolve domains through a proxy, it enables bypassing restrictions on the entire server or parts such as VPN panels, etc.
   - Additionally, this tool allows you to run multiple proxy layers simultaneously, in chains, randomly, etc., thereby reducing the risk of detection in security testing or specialized uses.
 - **SonChain** is a flexible solution for bypassing network restrictions that allows users to execute their commands seamlessly via a proxy without needing manual changes, while also benefiting from Tor’s dedicated ports.

<br> ─| **Limitations:**
  - **Some programs may not run due to the operational mechanisms of proxychains-Ng and socksify.**
  - **Currently, socksify supports UDP traffic transmission; however, due to Tor’s limitations, UDP traffic cannot be transmitted over Tor’s SOCKS proxy unless another SOCKS proxy is used.**
---
  
## Summary

**SonChain** at a glance,  
is a practical solution for bypassing network restrictions based on IP, DNS, geographic location, etc.  
By combining various tools and offering features such as temporary proxy execution of commands, temporary DNS changes, and support for Tor’s internal SOCKS|DNS, this script provides high flexibility in managing network traffic.  
The ability to use multiple proxy layers in chains, randomly, etc., not only enhances ease of use but also increases anonymity and resistance to detection in security or specialized scenarios, and additional features will be added to this project in the future.

</td>
</tr>
</table>

<a id="list"></a>

## 📑 Table of Contents

- [🚀 Project Overview](#about)
- [🔍 Introduction & Features](#Introduction)
- [📜 License](#license)
- [⚠️ Disclaimer](#Caution)
- [⚠️ Documentation](#docs)
- [✨ Features](#features)
- [🛠️ Prerequisites](#prerequisites)
- [⚙️ Installation](#installation)
- [📖 Menu & Options Guide](#guide)
- [📞 Contact](#contact)
- [🙏 Acknowledgements](#thanks)
- [🤝 Financial Support](#Financialsupport)
---

<br><br><br>

<a id="license"></a>
## 📜 License (MIT License)
**This project is released under the MIT License.**
- The copyright belongs to  
  Kalilovers [https://github.com/kalilovers] and any removal of the developer’s name, republishing, or modifications without proper attribution is prohibited.
- Forking, modifying, etc., is permitted as long as the original credits and owner information are maintained.
- To view the full MIT license text, please refer to [LICENSE](/LICENSE).

<br><br><br>

<a id="Caution"></a>
## ⚠️ Disclaimer:
This project is intended to facilitate communication between developers and users with restricted repositories and similar scenarios, network testing, and related security applications, as well as the separate use of all features of the **current** tools included in the script;
- **Tor - ProxyChains - Dante/Socksify** [Official Software]  
- **DNSSon & ProxySon**  [Created by the project developer]

<br> By combining various official tools or unofficially enhanced versions and custom-designed scripts.  
<br> in some cases, higher technical knowledge is required – it is also recommended to **carefully read the Documentation/Guide section**,

⚠️ **The user is solely responsible for any use or misuse of this project. The project developer and contributors assume no liability for any issues arising from improper or malicious use of these tools.**

[↪️ Back to Table of Contents](#list)




&nbsp;
<br><br><br>
<a id="features"></a>
## 🚀 Current Script Functionalities:
&nbsp;
<br>**🔥 "All of the following functionalities will be gradually optimized and enhanced"**
<br>**🔥 "Many features have been removed from the current version, which will be reintroduced in future versions as needed with optimization"**
- **✅ Installation/Removal, management, and configuration of Tor, ProxyChain-Ng, and Socksify**
- **✅ ProxySon and DnsSon scripts by Kalilovers have been designed for easier usage, to prevent DNS leaks during command execution, and for other user applications.**
- **✅ Specific status indicators for checking the status of available tools.**
- **📜 The configuration of Tor, ProxyChain-Ng, and Socksify is initially set up in a basic manner by the script during installation, after which the user can modify and enhance security, etc.**
- **✅ Use of interactive menus and the display of colorful reports for an improved user experience.**
- **✅ Ability to execute directly after installation with the command “sonchain”**
- **🐧 Tested on Ubuntu 18+ and Debian 8+ operating systems**
- **✅ Greater customization options for the available tools.**
- **✅ At various stages of operations, appropriate messages are displayed for further information.**
- **✅ Automatic temporary DNS configuration during installation, in case of issues with the server's current DNS settings.**
- **✅ Automatic resolution of APT tool issues on the server during installation.**
- **✅ Automatic removal of installed items in case of installation errors or if canceled by the user.**
- **✅ When manually editing configuration files, especially the TOR config file, a backup is taken first and then, before saving, a general review of the config content is performed by the script to ensure its correctness, which can be reverted if necessary.**
- **✅ All DNS changes or creation of Iptables rules by DNSSon and PROXYSON are performed as properly as possible and revert to normal at the end, temporarily and without removing file locks or sublinks or interfering with Iptables rules.**
- **✅ In the design and coding, the script has been developed to handle various conditions, increase operational speed, and certain aspects that require further enhancement will be implemented gradually.**

<br> **🔥 For more detailed explanations of the functionalities and usage guide, please refer to the following sections (at the bottom of the page).**

[↪️ Back to Table of Contents](#list)




&nbsp;
<br><br><br>
<a id="docs"></a>
                   
<div dir="ltr" style="text-align: left;">

<h2>📜 Documentation/Guide:</h2>

<ul>
  <li>
    <strong>Official ProxyChain-Ng:</strong><br>
    <a href="https://github.com/rofl0r/proxychains-ng/blob/master/README">
      README Link
    </a>
  </li>
  
  <li>
    <strong>Official Dante | Socksify:</strong><br>
    <a href="https://www.inet.no/dante/doc/1.4.x/socks.conf.5.html">
      socks.conf.5.html
    </a><br>
    <a href="https://www.inet.no/dante/doc/1.4.x/socksify.1.html">
      socksify.1.html
    </a><br>
    <a href="https://www.inet.no/dante/doc/">
      Main Documentation Page
    </a>
  </li>
  
  <li>
    <strong>Official Tor:</strong><br>
    <a href="https://docs.lightning.engineering/lightning-network-tools/lnd/configuring_tor">
      Configuring Tor with LND
    </a>
  </li>
</ul>

</div>



[↪️ Back to Table of Contents](#list)









&nbsp;
<br><br><br>
<a id="prerequisites"></a>

## 🛠️ Prerequisites
- 🐧**Ubuntu 18+ / Debian 8+** 
- 👑**sudo Access** 
- 🐍**Python 3.7+**

[↪️ Back to Table of Contents](#list)






&nbsp;
<br><br>
<a id="installation"></a>
## ⚙️ Installation | Removal | Run > via Command Line | Terminal
<br> 📦 **Script Installation**:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kalilovers/sonchain/main/install.sh)
```
<br> **Script Run**:
```bash
sonchain
```
<br> **Script Removal**:
```bash
sudo sonchain --uninstall
```

---

<br> ▶️ Run commands with **proxychains**:
```bash
proxychains4 
```
Example:
```bash
proxychains4 apt update
```

<br> ▶️ Run commands with **Socksify**:
```bash
socksify 
```
Example:
```bash
socksify apt update
```

<br> ▶️ Run commands with **Prosyson**:
```bash
prosyson 
```
Example:
```bash
prosyson apt update
```

<br> ▶️ Run commands with **Dnsson**:
```bash
dnsson 
```
Example:
```bash
dnsson dig google.com
```

<br> ▶️ Using the **nyx** tool for enhanced Tor monitoring:
```bash
nyx 
```

- [↪️ Back to Table of Contents](#list)












&nbsp;
<br><br><br>

<a id="guide"></a>

## 📋 Guide for Menus and Options

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/main.png)

&nbsp;




<details>
<summary>1️⃣ Status</summary>
  
  🧰 **This menu is used for 'Checking the status of services (Tor, ProxyChains, etc.)'.**

  &nbsp;
  
  ![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/status.png)




&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">1 | Tor Status</summary>
  
  <p dir="ltr" style="text-align: left;">
    
🧰 **This option is used to check the 'Tor Status'.**  
  <br><br> For example, as shown in the image below:
  </p>
  
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torstatus.png">
  </p>
  
  <ul dir="ltr" style="text-align: left;">
    <li><b>Tor Service Section:</b> The status of the Tor service (Running means it is active)</li>
    <li><b>SOCKS Proxy Settings Section:</b> The port and IP of Tor’s SOCKS proxy (displayed only if valid or available)</li>
    <li><b>DNS Proxy Settings Section:</b> The port and IP of Tor’s DNS Proxy (displayed only if valid or available)</li>
    <li><b>General Settings Section:</b> Other Tor configuration settings – such as displaying the log path when enabled, etc.</li>
    <li><b>If not present:</b> If Tor or the <code>torrc</code> configuration file does not exist, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>
  
&nbsp;




<details>
<summary dir="ltr" style="text-align: left;">2 | Socksify Status</summary>

<p dir="ltr" style="text-align: left;">
  
  🧰 **This option is used to check the 'Socksify Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifystatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Config File Section:</b> The path to the configuration file</li>
    <li><b>SOCKS Settings Section:</b> The port and IP of the SOCKS output (displayed only if valid or available)</li>
    <li><b>DNS Settings Section:</b> The DNS resolve protocol (displayed only if valid or available)</li>
    <li><b>Logging Section:</b> Displays the log path if enabled, etc.</li>
    <li><b>If not present:</b> If <code>dante-client</code> or the <code>socks.conf</code> configuration file is missing, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

&nbsp;





<details>
  <summary dir="ltr" style="text-align: left;">3 | ProxyChains Status</summary>

  <p dir="ltr" style="text-align: left;">
  
  🧰 **This option is used to check the 'ProxyChains Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainsstatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Config File Section:</b> The path to the configuration file</li>
    <li><b>General Settings Section:</b> Displays various settings; for example, in this image, "active proxies" indicates the number of active proxies (displayed only if valid or available)</li>
    <li><b>Recent Proxies Section:</b> Shows up to 5 proxies with their port and IP (passwords, if any, are displayed)</li>
    <li><b>Connection Status:</b> A connectivity test is performed via the proxies to 1.1.1.1 on port 80, and the result is shown –  errors may occur</li>
    <li><b>If not present:</b> If <code>PROXYCHAINS</code> or the <code>proxychains.conf</code> configuration file is missing, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">4 | ProxySon Status</summary>

  <p dir="ltr" style="text-align: left;">
  
  🧰 **This option is used to check the 'ProxySon Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonstatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Destination Section:</b> The DNS destination set for temporary configuration in <code>resolv.conf</code> and in <code>iptables</code> when using this tool.</li>
    <li><b>Command Section:</b> Displays the command configured to be executed by <code>proxyson</code>.</li>
    <li><b>IPTables Rules Section:</b> Shows the current status of <code>iptables</code> rules – in the current image, "Not Active" indicates that the rules are not currently in use, which is normal since they are applied temporarily.</li>
    <li><b>If not present:</b> If the <code>proxyson</code> file does not exist, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">5 | DnsSon Status</summary>

  <p dir="ltr" style="text-align: left;">
  
  🧰 **This option is used to check the 'DnsSon Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonstatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Destination Section:</b> The DNS destination set for temporary configuration in <code>resolv.conf</code> and in <code>iptables</code> when using this tool.</li>
    <li><b>IPTables Rules Section:</b> Shows the current status of <code>iptables</code> rules – in the current image, "Not Active" indicates that the rules are not in use, which is normal since they are applied temporarily.</li>
    <li><b>If not present:</b> If the <code>DnsSon</code> file does not exist, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

</details>

&nbsp;











<details>
<summary>2️⃣ Auto Setup</summary>
  
  🧰 **This menu is used for 'Automatic Installation and Synchronization of ProxyChains or Socksify with Tor'.**
  
  <br> 🔹 **If the process fails or is canceled by the user, any installed components will be removed**
  <br> 🔹 **If connection fails due to DNS issues, the script will first attempt to temporarily adjust DNS settings to resolve the issue**
  <br> 🔹 **After checking your server’s connectivity to the official Tor repository, the script will install the latest version; if unsuccessful (due to censorship, destination blockage, etc.), it will install via your system’s official repositories.**
  
  &nbsp;
  
  ![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/autosetup.png)




&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">1 | Setup Dante|Socksify + Tor</summary>

  <p dir="ltr" style="text-align: left;">
  
  🧰 **This option is used for 'Automatic Installation and Synchronization of Socksify, Dnsson, and Proxyson with Tor'.**
  
  <br><br> To begin after selecting option 1:
  <br><br> 1_ Confirm the prompt > if confirmed, "Tor, Socksify, Dnsson, and Proxyson" will be cleanly removed for reinstallation.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksify+tor1.png">
  </p>

  <br> 2_ After installation, you will be prompted to set the port-IP values for <code>Socksport</code> and <code>Dnsport</code> of the <code>tor</code> software. **If an incorrect or invalid value is entered, a warning will be issued; if you press 'enter' without entering a value, a suitable value will be automatically set (recommended).**
  <br> In the example below, I pressed 'Enter' for 3 items to auto-set and mistakenly entered '0' for one item; after a warning and re-prompt, I pressed 'Enter' again:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksify+tor2.png">
  </p>

  <br> 3_ After installation completes, you will see the configured values (also visible in the Status menu).
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksify+tor3.png">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksify+tor4.png">
  </p>

</details>

&nbsp;








<details>
  <summary dir="ltr" style="text-align: left;">2 | Setup ProxyChains + Tor</summary>

  <p dir="ltr" style="text-align: left;">
  
  🧰 **This option is used for 'Automatic Installation and Synchronization of ProxyChains-Ng with Tor'.**  

  <br><br> To begin after selecting option 2:
  <br><br> 1_ Confirm the prompt > if confirmed, "Tor and ProxyChains" will be cleanly removed for reinstallation.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chains+tor1.png">
  </p>

  <br> 2_ After installation, you will be prompted to set the port-IP values for <code>Socksport</code> and <code>Dnsport</code> of the <code>tor</code> software. **If an incorrect or invalid value is entered, a warning will be issued; if you press 'enter' without entering a value, a suitable value will be automatically set (recommended).**
  <br> In the example below, I pressed 'Enter' for 3 items to auto-set and mistakenly entered '0' for one item; after a warning and re-prompt, I pressed 'Enter' again:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chains+tor2.png">
  </p>

  <br> 3_ After installation completes, you will see the configured values (also visible in the Status menu).
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chains+tor3.png">
  </p>

</details>

</details>

&nbsp;










<details>
<summary>3️⃣ Tor Setup</summary>

  <p dir="ltr" style="text-align: left;">
   
 🧰 **This menu is designed for 'Tor Management'.**
 
![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/tormenu.png)


&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">1 | Tor Status</summary>

  <p dir="ltr" style="text-align: left;">

🧰 **This option is used to 'Check Tor Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torstatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Tor Service Section:</b> Displays the status of the Tor service (Running indicates it is active)</li>
    <li><b>SOCKS Proxy Settings Section:</b> Shows the port and IP for Tor’s SOCKS proxy (displayed only if valid or present)</li>
    <li><b>DNS Proxy Settings Section:</b> Shows the port and IP for Tor’s DNS Proxy (displayed only if valid or present)</li>
    <li><b>General Settings Section:</b> Other Tor configuration settings – such as displaying the log path if enabled, etc.</li>
    <li><b>If not present:</b> If Tor or the <code>torrc</code> configuration file is missing or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">2 | Install Tor</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Install Tor'.**

 <br> 🔹 **If the process fails or is canceled by the user > any installed components will be removed**
 <br> 🔹 **If connection fails due to DNS issues > the script will first attempt to temporarily adjust DNS settings to resolve the issue**
 <br> 🔹 **After checking your server’s connectivity to the official Tor repository, the script will install the latest version; if unsuccessful (due to censorship, destination blockage, etc.), it will install via your system’s official repositories.**

  <br><br> To begin after selecting option 2:
  <br><br> 1_ Confirm the prompt > if confirmed, "Tor" will be cleanly removed for reinstallation.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup2.png">
  </p>

  <br> 2_ After installation, you will be prompted to set the port-IP values for <code>Socksport</code> and <code>Dnsport</code> of the <code>tor</code> software. **If an incorrect or invalid value is entered, a warning will be issued; if you press Enter without entering a value, a suitable value will be set automatically (recommended).**
  <br> In the example below, I pressed 'Enter' for 4 items to auto-set , used 'Enter':
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup2-2.png">
  </p>

  <br> 3_ After installation completes, you will see the configured values (also visible in the Status menu).
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup2-3.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">3 | Manual Configuration</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used for 'Manual Editing of the Tor Config' located at "etc/tor/torrc".**

 <br> 🔹 **After the new config is auto-validated by the script, if the edited contents are invalid, the script will offer to restore the config file**
 <br> 🔹 **If the config file or Tor itself does not exist, an appropriate message is displayed**
 <br> 🔹 **Avoid making non-standard or erroneous changes**

  <br><br> To begin after selecting option 3:
  <br><br> 1_ After finishing the edit, press ctrl+c and confirm with y; if the new contents are valid, you will be prompted with 3 questions regarding synchronizing 'Socksify - dnsson - proxyson' with the new Tor settings, which you can confirm with 'y or Enter' or reject with 'n'.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup3.png">
  </p>
  
  <br> For example, as shown in the image, the value '127.119.179.222:9038' was synchronized as the 'DNS' value for 'proxyson - dnsson', but not for 'Socksify' (likely due to the absence of the config file or Socksify itself).

  <br> 2_ If there is an error in the Tor config (note that the script only validates the SOCKS and 'dns' sections), the script will offer to restore the settings; if you do not confirm, the settings will still be applied but synchronization will not occur.
  <br> In the example below, I pressed 'Enter' for 3 items to auto-set and mistakenly entered '0' for one item, then after a warning and a re-prompt, used 'Enter':
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup3-2.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">4 | Stop Tor</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Stop the Tor Service'. If Tor is not present, an appropriate message is displayed.**
&nbsp;

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup4.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">5 | Restart Tor</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Restart the Tor Service'. If Tor is not present, an appropriate message is displayed.**

**🔹 Additionally, you can use this option to change Tor's nodes .**

&nbsp;

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup5.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">6 | Remove Tor</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Remove Tor'.**

&nbsp;

Confirm the prompt > if confirmed, "Tor" will be removed.

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup6.png">
  </p>

</details>

</details>

&nbsp;










<details>
<summary>4️⃣ Dante'Socksify' Setup</summary>

  <p dir="ltr" style="text-align: left;">
   
 🧰 **This menu is designed for 'Socksify Management'.**
&nbsp;

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifymenu.png)

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">1 | Socksify Status</summary>

  <p dir="ltr" style="text-align: left;">
   
  🧰 **This option is used to 'Check the Socksify Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifystatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Config File Section:</b> The path to the config file</li>
    <li><b>SOCKS Settings Section:</b> The port and IP of the SOCKS output (displayed only if valid or available)</li>
    <li><b>DNS Settings Section:</b> The DNS Resolve protocol (displayed only if valid or available)</li>
    <li><b>Logging Section:</b> Displays the log path if enabled, etc.</li>
    <li><b>If not present:</b> If <code>dante-client</code> or the <code>socks.conf</code> config file is missing, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">2 | Install Socksify</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Install Socksify'.**

 <br> 🔹 **If the process fails or is canceled by the user > any installed components will be removed**
 <br> 🔹 **If connection fails due to DNS issues > the script will first attempt to temporarily adjust DNS settings to resolve the issue**

  <br><br> To begin after selecting option 2:
  <br><br> 1_ Confirm the prompt > if confirmed, "Dante|Socksify" will be removed cleanly for installation.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup2.png">
  </p>

  <br> 2_ After installation, you will be prompted to synchronize Socksify settings with Tor. If confirmed and valid Tor settings exist, synchronization will occur; otherwise, you will need to manually enter the Socksify output IP and port.
  <br> In the example below, I confirmed synchronization:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup2-2.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">3 | Edit Configuration</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used for 'Manual Editing of the Socksify Config' located at "etc/socks.conf".**

 <br> 🔹 **If the config file or Socksify itself does not exist, an appropriate message is displayed**
 <br> 🔹 **Avoid making non-standard or erroneous changes**

  <br><br> To begin after selecting option 3:
  <br><br> After finishing editing, press ctrl+c and confirm with y; the settings will be saved without content validation **so please be careful when editing settings**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup3.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">4 | Change SOCKS IP/Port</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used for 'Changing the SOCKS IP/Port' for the Socksify output in the config at "etc/socks.conf".**

 <br> 🔹 **If the config file or Socksify itself does not exist, an appropriate message is displayed**
 <br> 🔹 **The script somewhat prevents you from entering incorrect information**
 <br> 🔹 **Avoid making non-standard or erroneous changes**

  <br><br> To begin after selecting option 4:
  <br><br> Enter your desired values; for example, as shown below.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup4.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">5 | Change DNS Protocol</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Change the DNS PROTOCOL' in the Socksify config located at "etc/socks.conf".**

 <br> 🔹 **If the config file or Socksify itself does not exist, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**
 <br> 🔹 **Avoid making changes if you lack sufficient knowledge**
  
  <br><br> To begin after selecting option 5:
  <br><br> Choose your desired protocol; in the example below, I selected TCP.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup5.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">6 | Sync with Tor</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Synchronize the Socksify Config' (Socks IP and Port) with Tor settings.**

 <br> 🔹 **If the config file, Tor, or Socksify does not exist, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**

  <br><br> To begin after selecting option 6:
  <br><br> In the example below, synchronization has been performed and the new output is displayed.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup6.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">7 | Remove Dante</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Remove Socksify'.**

&nbsp;

Confirm the prompt > if confirmed, "Socksify" will be removed.

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup7.png">
  </p>

</details>

</details>


&nbsp;











<details>
<summary>5️⃣ ProxyChains Setup</summary>

  <p dir="ltr" style="text-align: left;">
   
 🧰 **This menu is designed for 'ProxyChains-Ng Management'.**
&nbsp;

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainsmenu.png)

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">1 | Status</summary>

  <p dir="ltr" style="text-align: left;">
   
  🧰 **This option is used to 'Check ProxyChains Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainsstatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Config File Section:</b> The path to the configuration file</li>
    <li><b>General Settings Section:</b> Displays various settings; for example, in this image, "active proxies" indicates the number of active proxies (displayed only if valid or available)</li>
    <li><b>Recent Proxies Section:</b> Shows the port and IP of the proxy output (up to 5 proxies are displayed), and if a password exists, it is also shown</li>
    <li><b>Connection Status Section:</b> A connectivity test is performed through the proxies to 1.1.1.1 on port 80, and the result is displayed – errors may occur</li>
    <li><b>If not present:</b> If <code>PROXYCHAINS</code> or the <code>proxychains.conf</code> configuration file is missing, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">2 | Install ProxyChains</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Install ProxyChains-Ng'.**

 <br> 🔹 **If the process fails or is canceled by the user, any installed components will be removed**
 <br> 🔹 **If connection fails due to DNS issues, the script will first attempt to temporarily adjust DNS settings to resolve the problem**

  <br><br> To start after selecting option 2:
  <br><br> 1_ Confirm the prompt > if confirmed, "ProxyChains" will be cleanly removed for reinstallation.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup2.png">
  </p>

  <br> 2_ After installation completes, you will be prompted to synchronize ProxyChains settings with Tor; if confirmed and valid Tor settings exist, synchronization will occur, otherwise you must manually enter the ProxyChains output IP and port.
  <br> In the example below, I confirmed synchronization:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup2-2.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">3 | Edit Configuration</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used for 'Manual Editing of the ProxyChains configuration' located at "etc/proxychains.conf".**

 <br> 🔹 **If the configuration file or ProxyChains itself does not exist, an appropriate message is displayed**
 <br> 🔹 **Avoid making non-standard or erroneous changes**

  <br><br> To start after selecting option 3:
  <br><br> After finishing the edit, press ctrl+c and confirm with y; the settings will be saved without content validation **so please be careful when editing settings**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup3.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">4 | Change Chain Type (Strict/Dynamic)</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Change the Chain Type' in the ProxyChains configuration at "etc/proxychains.conf".**

 <br> 🔹 **If the configuration file or ProxyChains itself does not exist, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**
 <br> 🔹 **Avoid making changes if you lack sufficient knowledge**

  <br><br> To start after selecting option 4:
  <br><br> Choose your desired chain type; in the example below, I selected Dynamic Chain.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup4.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">5 | Change Quiet Mode (Active/InActive)</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Toggle Quiet Mode' in the ProxyChains configuration at "etc/proxychains.conf".**

 <br> 🔹 **If the configuration file or ProxyChains itself does not exist, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**
 <br> 🔹 **Avoid making changes if you lack sufficient knowledge**

  <br><br> To start after selecting option 5:
  <br><br> The mode toggles on each execution without the need for input.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup5.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">6 | Change DNS_Proxy Mode</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Change the DNS_Proxy Mode' in the ProxyChains configuration at "etc/proxychains.conf".**

 <br> 🔹 **If the configuration file or ProxyChains itself does not exist, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**
 <br> 🔹 **Avoid making changes if you lack sufficient knowledge**

  <br><br> To start after selecting option 6:
  <br><br> Choose your desired mode; in the example below, I selected proxy_dns mode.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup6.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">7 | Add Custom Proxy</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Add a Custom Proxy' (of type Socks or HTTP, with or without authentication) to the ProxyChains configuration at "etc/proxychains.conf".**

 <br> 🔹 **If the configuration file or ProxyChains itself does not exist, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**
 <br> 🔹 **Avoid adding proxies with incorrect details**

  <br><br> To start after selecting option 7:
  <br><br> Enter your desired values; in the example below, I entered my proxy’s IP and Port, then confirmed the prompt for adding a username and password (you can decline if not using authentication). After entering the username and password, I selected the proxy protocol, and it was finally added. **Avoid adding proxies with incorrect details.**
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup7.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">8 | Sync with Tor</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Synchronize the ProxyChains configuration' (i.e. its DNS settings) with the Tor settings in Dnsport.**

 <br> 🔹 **If the configuration file, Tor, or ProxyChains is missing, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**

  <br><br> To start after selecting option 8:
  <br><br> In the example below, synchronization was not performed (because it is already synchronized and no re-sync is needed).
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup8.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">9 | Remove ProxyChains</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Remove ProxyChains-Ng'.**

&nbsp;

Confirm the prompt > if confirmed, "ProxyChains" will be removed.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup9.png">
  </p>

</details>

</details>











&nbsp;

<details>
<summary>6️⃣ DnsSon Setup</summary>

  <p dir="ltr" style="text-align: left;">
   
 🧰 **This menu is designed for 'DnsSon Management'.**

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonmenu.png)

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">1 | DNSSON Status</summary>

  <p dir="ltr" style="text-align: left;">
   
  🧰 **This option is used to 'Check DnsSon Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonstatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Destination Section:</b> The DNS destination set for temporary configuration in <code>resolv.conf</code> and in <code>iptables</code> when using this tool.</li>
    <li><b>IPTables Rules Section:</b> Displays the current status of <code>iptables</code> rules – in the current image, "Not Active" indicates that the rules are not in use, which is normal since they are applied temporarily.</li>
    <li><b>If not present:</b> If the <code>DnsSon</code> file does not exist, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">2 | Install DnsSon</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Install DnsSon'.**

  <br><br> To start after selecting option 2:
  <br><br> 1_ Confirm the prompt (if DnsSon is already installed, this prompt will appear) > if confirmed, "DnsSon" will be cleanly removed for reinstallation.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup2.png">
  </p>

  <br> 2_ After installation completes, you will be prompted to synchronize DnsSon settings with the Tor Dnsport settings; if confirmed and valid Tor settings exist, synchronization will occur, otherwise you must manually enter the DNS IP and port.
  <br> In the example below, I confirmed synchronization:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup2-2.png">
  </p>
  <br> And the DNS details were set as the Nameserver in DnsSon.

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">3 | Change Destination</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to change the 'Destination' (i.e. DNS) used in DnsSon.**

 <br> 🔹 **If the DnsSon configuration is missing, an appropriate message is displayed**
 <br> 🔹 **Avoid making non-standard or erroneous changes**

  <br><br> To start after selecting option 3:
  <br><br> After entering the IP and PORT values, they are saved without validating the content **so please be cautious when editing settings**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup3.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">4 | Synchronize With Tor</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Synchronize the DNS settings in the DnsSon configuration with the Tor Dnsport settings'.**

 <br> 🔹 **If the configuration file, Tor, or DnsSon is missing, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**

  <br><br> To start after selecting option 4:
  <br><br> In the example below, synchronization was performed and the new output is displayed.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup4.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">5 | Remove DnsSon</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Remove DnsSon'.**

&nbsp;

Confirm the prompt > if confirmed, "DnsSon" will be removed.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup5.png">
  </p>

</details>

</details>

&nbsp;











<details>
<summary>7️⃣ ProxySon Setup</summary>

  <p dir="ltr" style="text-align: left;">
   
 🧰 **This menu is designed for 'ProxySon Management'.**

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonmenu.png)

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">1 | ProxySon Status</summary>

  <p dir="ltr" style="text-align: left;">
   
  🧰 **This option is used to 'Check ProxySon Status'.**  
  <br><br> For example, as shown in the image below:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonstatus.png">
  </p>

  <ul dir="ltr" style="text-align: left;">
    <li><b>Destination Section:</b> The DNS destination set for temporary configuration in <code>resolv.conf</code> and in <code>iptables</code> when using this tool.</li>
    <li><b>Command Section:</b> Displays the command configured to be executed by <code>proxyson</code>.</li>
    <li><b>IPTables Rules Section:</b> Shows the current status of <code>iptables</code> rules – in the current image, "Not Active" indicates that the rules are not in use, which is normal since they are applied temporarily.</li>
    <li><b>If not present:</b> If the <code>proxyson</code> file is missing, or if other issues occur, an appropriate message is displayed.</li>
  </ul>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">2 | Install ProxySon</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Install ProxySon'.**

  <br><br> To start after selecting option 2:
  <br><br> 1_ Confirm the prompt (if ProxySon is already installed, this prompt will appear) > if confirmed, "ProxySon" will be cleanly removed for reinstallation.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup2.png">
  </p>

  <br> 2_ After installation completes, you will be prompted to synchronize ProxySon settings with the Tor Dnsport settings; if confirmed and valid Tor settings exist, synchronization will occur, otherwise you must manually enter the DNS IP and port.
  <br> 3_ Then you will be prompted to enter the command you wish ProxySon to use (by default, "socksify" is used); for example, you can enter "proxychains4", or simply press 'Enter' to use the default.
  <br> In the example below, I confirmed synchronization and pressed 'Enter' for the second prompt:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup2-2.png">
  </p>
  <br> And the DNS details were set as the Nameserver in ProxySon.
  <br> Also, the default command "socksify" was set as the command to be executed.

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">3 | Change Destination</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to change the 'Destination' (i.e. DNS) used in ProxySon.**

 <br> 🔹 **If the ProxySon configuration is missing, an appropriate message is displayed**
 <br> 🔹 **Avoid making non-standard or erroneous changes**

  <br><br> To start after selecting option 3:
  <br><br> After entering the IP and PORT values, they are saved without content validation **so please be cautious when editing settings**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup3.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">4 | Change Command</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to change the 'Execution Command' configured in ProxySon.**

 <br> 🔹 **If the configuration file, Tor, or ProxySon is missing, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**

  <br><br> To start after selecting option 4:
  <br><br> In the example below, the changes were applied and the new output is displayed.
  <br> I entered the command "proxychains4".
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup4.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">5 | Sync with Tor</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to 'Synchronize the DNS settings in the ProxySon configuration with the Tor Dnsport settings'.**

 <br> 🔹 **If the configuration file, Tor, or ProxySon is missing, an appropriate message is displayed**
 <br> 🔹 **For more information, refer to the documentation**

  <br><br> To start after selecting option 5:
  <br><br> In the example below, synchronization was performed and the new output is displayed.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup5.png">
  </p>

</details>

&nbsp;

<details>
  <summary dir="ltr" style="text-align: left;">6 | Remove ProxySon</summary>

  <p dir="ltr" style="text-align: left;">
   
🧰 **This option is used to remove ProxySon.**

&nbsp;

Confirm the prompt > if confirmed, "ProxySon" will be removed.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup6.png">
  </p>

</details>

</details>







&nbsp;

<details>
<summary>8️⃣ Update Script</summary>

  <p dir="ltr" style="text-align: left;">
   
 🧰 **This option is designed to update the Sonchain script.**

  <br> ♻️ **After selecting this option, confirm the update prompt to check for and install the latest version.**
  <br> ♻️ **This option only updates the Sonchain script itself and does not affect the tools installed by the script.**

</details>







&nbsp;

<details>
<summary>9️⃣ Uninstall</summary>

  <p dir="ltr" style="text-align: left;">
   
 🧰 **This menu is designed for 'Uninstalling the script or the tools installed by the script'.**

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/uninstallmenu.png)

  <br><br> 🗑 **Select the desired option for removal and confirm to begin the uninstallation process.**

</details>

&nbsp;



[↪️ Back to Table of Contents](#list)




























<br><br><br>

&nbsp;
<a id="thanks"></a>
## 🙏 Thanks and appreciation

Special thanks to:
- **Channel and group https://t.me/OPIran_official :** which helps increase public knowledge by sharing practical tools, projects and technical content.
- **Channel and site [Digitalvps](https://t.me/digital_vps) :** which provided significant assistance by providing the equipment needed for easier testing and review.



<br><br><br>
<a id="contact"></a>
<h2>📞 Contact me</h2>
<p>
<ul>
<li>Use the GitHub Issue section to contact me.
</ul>
</p>






 

<br><br><br>
<a id="Financialsupport"></a>
## 💰 Donation
🤝 ****Support the project creator and further development:****
 
- **Bitcoin :**
```bash
bc1q83yf8k5klulj5n2nh7zmergjsjcwj72x4h8a6c
```
- **Tron TRX Or USDT** :
```bash
TAodRbeJmtj7Lj48TZeds84BKmYVtXpdaJ
```

[↪️ Return to table of contents](#list)





