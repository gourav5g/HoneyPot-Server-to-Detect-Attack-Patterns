**NOTE: Two Projects are Listed Bewlo in This reporistory**
---

# HoneyPot-Server-to-Detect-Attack-Patterns )  - By Gourav Niroula (Project 1) 
A lightweight honeypot server designed to attract, log, and analyze malicious traffic to uncover common attack patterns and techniques. Ideal for research, threat intelligence, and intrusion detection.  


# 🛡️ A Lightweight Honeypot Server

A lightweight honeypot server designed to attract, log, and analyze malicious traffic to uncover common attack patterns and techniques. Ideal for research, threat intelligence, and intrusion detection.

---

## ☁️ Honeypot (T-Pot) with AWS

### 🧪 HoneyPot Server to Detect Attack Patterns – By Gourav Niroula

- **Objective:** Deploy a honeypot to simulate vulnerable services and log attackers.

- **Tools:**
  - Cowrie or custom Python scripts
  - SSH/FTP emulation

- **Mini Guide:**
  - a. Deploy honeypot on a VM  
  - b. Log connections, IPs, attempted commands  
  - c. Analyze log files for repeated attempts  
  - d. Use fail2ban to block real threats  
  - e. Visualize IP geolocation of attackers

- **Deliverables:**  
  Running honeypot + detailed logs + visual attack reports.


![1](https://github.com/user-attachments/assets/552d6629-0fd2-40f8-90d3-348645e7bc7c)

# 🛡️ How Honeypots Work: Real Attacks, Safe Systems, and the T-Pot Advantage

## 🔍 Inside the Trap: Understanding Honeypots with Real-World Examples

## 🚀 Using T-Pot to Attract and Analyze Real Cyber Attacks — A Beginner’s Guide

## 🖥️ Deploying T-Pot Honeypot Safely on Ubuntu: Real Threats in a Controlled Lab

---

## 📘 Introduction

➤ What is a honeypot? Why is it used in cybersecurity?

---

## ⚙️ What is T-Pot and How Does It Work?

➤ Explain multi-honeypot framework and logging with ELK stack.

---

## ❓ Can Hackers Really Attack My System?

➤ Clarify doubts about real vs virtual attacks.

---

## 🧠 Real-World Analogy: Honeypot is a Fake Shop

➤ Use your example here (see below).

---

## 💡 Running T-Pot on a Windows System Safely

➤ Explain VirtualBox + Ubuntu method to isolate real machine.

---

## 🕒 Why Do Companies Run T-Pot 24/7?

➤ SOC / Threat Intelligence / Logging / Alerting reasons.

---

## 🧾 Conclusion: Safe Experimentation, Real Threat Insight

➤ Honeypots are powerful tools for both learning and real defense.

---

## 🏪 Real-World Analogy: Honeypot is a Fake Shop

Imagine setting up a fake shop inside your house, designed to look real from the outside. You place attractive signs, open the door halfway, and even display fake items in the window.

Outsiders walking by — especially those looking to steal — see this and try to break in. But here’s the trick: the fake shop leads nowhere. It’s not connected to the rest of your home.

It’s just a setup to lure potential thieves, monitor what they do, and collect their methods — all without putting your real home at risk.

That’s exactly how a honeypot works in cybersecurity. It looks like a vulnerable system to attackers, but it’s isolated from your real machines. While attackers believe they’re hacking something valuable, you’re actually recording their every move.

---

## ☁️ Launching a New Instance on ECE (Elastic Compute Environment)

To deploy the T-Pot honeypot safely on a cloud machine, I started by launching a new virtual instance using my ECE cloud panel.

---

### 🛠️ Step-by-Step Instance Creation

**11.** Clicked on “Launch Instance”  
From the ECE dashboard, I clicked on the “Launch Instance” button to begin creating a new virtual server.

![2](https://github.com/user-attachments/assets/97e32146-379a-42dc-bb25-ade075683f55)

**2.** Selected the Operating System: **Ubuntu**  
In the system configuration section, I chose **Ubuntu** as the operating system since **T-Pot** is designed to run on Ubuntu.

![3](https://github.com/user-attachments/assets/31ff1a37-e05f-4108-a70f-0abdeea71cfc)

**3.** Set the Storage Size to **128 GB**  
I allocated **128 GB** of disk space to ensure there is enough room for the honeypot tools, logs, and dashboards (like **Kibana** and **ELK stack** data).

![4](https://github.com/user-attachments/assets/a3d33a27-c53c-453c-856d-5077e4595fc6)

**4.** Chose an **IP Address**  
I selected my IP address for the instance so that it could be accessible over the internet — allowing real-world attackers to reach the honeypot services exposed by **T-Pot**.

![5](https://github.com/user-attachments/assets/bcd61ee1-4b20-45c5-bc95-ffa19c828b47)

**5.** Generated a New **SSH Key Pair**  
I created a new key pair to securely access the virtual machine via **SSH**. This private key would be downloaded and used later for login.

![6](https://github.com/user-attachments/assets/39f9f98e-bf18-4a86-964c-72b640479aba)

**6.** Selected the Instance Type: **t3.XLarge Tier**  
I picked the **t3.XLarge** instance type to provide sufficient CPU and memory resources for running multiple honeypots and dashboards smoothly.

**7.** Reviewed the Configuration  
After verifying all the selected options (OS, tier, storage, key, and IP), I proceeded to launch the instance.

**8.** Clicked “Launch Instance”  
Finally, I clicked the **“Launch Instance”** button to deploy the virtual machine. Within a few minutes, the instance was up and running, ready for **SSH access** and **T-Pot installation**.

![7](https://github.com/user-attachments/assets/babdb5a2-56b1-4117-8927-0bd9042ebee0)

![8](https://github.com/user-attachments/assets/a814daf7-d6e3-4085-98fe-04e41d4aed12)

**9.** Accessed the Instance via **SSH Client**  
After that, I went to the **SSH client**, copied the full connection command, and pasted it into the **Command Prompt** or **Terminal** to access the instance.

![9](https://github.com/user-attachments/assets/df98c9e5-d84e-4aae-bbbc-8360dae68780)

**🔐 SSH Login Command to Access the Instance:**

```bash
ssh -i "your-key.pem" ubuntu@<Public-IP>
```

![10](https://github.com/user-attachments/assets/d33809c6-6f3a-4d89-9f4f-70d11e0dbde6)

![11](https://github.com/user-attachments/assets/a58f9c2a-fbf2-4b02-b4b8-fd42134f4991)

After that run this command; 

**🔄 Update the System Packages:**

```bash
sudo apt update
```

![12](https://github.com/user-attachments/assets/73992e6e-3030-48f7-8997-5201c71acb28)

Then I did  -- sudo apt update command

![13](https://github.com/user-attachments/assets/46f1a0f6-e99b-4680-b234-fc4a004a1c20)

Once our system is updated then go to the this website and paste the github 
repositry https://github.com/telekom-security/tpotce and clone it 
https://github.com/telekom-security/tpotce.git

![14](https://github.com/user-attachments/assets/68ccff44-e27f-4ab2-96e3-09cb2460787c)

after clone this repositry go the tpotce directory run this command 
./install.sh 
and click on y

![15](https://github.com/user-attachments/assets/856adcce-dc93-4e05-b1ad-961260dab066)

select according to the image and set username and password for tpot

![16](https://github.com/user-attachments/assets/1ebf3b0a-a9da-468e-976b-de6661ddb862)

You can see here the tpot is successfully installed 
ignore sudo reboot now for now ...

![17](https://github.com/user-attachments/assets/23e997db-44b8-4586-91d7-e299d83c07b2)

Configuring Inbound Rules After T-Pot Installation 
**🌐 Configuring Inbound Rules for T-Pot Access**

Once the **T-Pot honeypot** was successfully installed on my Ubuntu server, the next crucial step was to configure **inbound rules** to allow external traffic to reach the services provided by T-Pot.  

This is done through the **Security Group** or **firewall settings** in the cloud panel (**ECE** in my case).  

Here’s how I set it up:  
Go to the **EC2 instance**, select **Security**, and click according to the arrow.

![18](https://github.com/user-attachments/assets/b5f91a03-4d94-4551-b4bf-607d91038e10)

## 🔐 Why I Opened Ports 64295 and 64297 in AWS Inbound Rules

After successfully installing T-Pot honeypot on my Ubuntu EC2 instance, I had to configure inbound rules to allow traffic to specific ports used by T-Pot’s services and dashboards. Here’s why these particular ports were chosen:

### ⚙️ Purpose of Each Port

- **Port 64295 (TCP)** → This port is used by the **T-Pot Web Cockpit (Admin UI)**. It provides an overview of the system status, uptime, and resource usage. It’s the main dashboard where I can monitor the honeypot’s performance and system health in real time.

- **Port 64297 (TCP)** → This port is dedicated to the **Kibana Dashboard**, which is part of the ELK stack integrated with T-Pot. It visualizes the captured logs and attack data, showing rich visual analytics about the threats interacting with the honeypots.

These ports are not standard (like port 80 or 22), which makes them less predictable and slightly more secure by default.

> **Note:**  
> Two times click on **Add Rules** to open these ports.

![19](https://github.com/user-attachments/assets/db3c96e6-22f3-4491-a8bc-3558d028f9a7)

![20](https://github.com/user-attachments/assets/2a7ed9e8-f444-482d-b124-959ace29c3ac)

![21](https://github.com/user-attachments/assets/214f5762-207b-4db3-9513-a26f0e9fdd32)

## 🔐 Logging In After Firewall Setup

Once the inbound rules were saved, I connected to the T-Pot server via SSH using this command:

```bash
ssh -i "keys2.pem" ubuntu@ec2-13-204-67-53.ap-south-1.compute.amazonaws.com -p 64295
```
 Breakdown:
-i "keys2.pem" → Path to the private key file for authentication
ubuntu@... → Default user and public IP/domain of my EC2 instance
-p 64295 → Custom SSH port (T-Pot replaces the default port 22 with 64295 for added stealth)

![22](https://github.com/user-attachments/assets/5ea85c6c-2c79-45d1-b2b4-b4bce744d737)

Go the ec2 instance and copy the ipv4 address and

![23](https://github.com/user-attachments/assets/b021211e-5de2-4b4b-8fe2-dfb8a139e08c)

run https://13.x.x.x:64297

![24](https://github.com/user-attachments/assets/2e8d766d-f8b6-4015-86ca-9334bebb848c)

After that login with username and password you created this before when we installing tpot

![25](https://github.com/user-attachments/assets/dcc6118d-c85b-4bf4-bde8-f6c7728316ba)

## 🌍 Real-Time Global Threat Monitoring via T-Pot Attack Map

Once the honeypot was fully installed and the Kibana dashboard was accessible via port **64297**, I opened the **T-Pot Attack Map** in the browser using the URL:
https://<public-ip>:64297/map/ 
In my case: 
https://13.204.67.53:64297/map/ 
Note: You might see a security warning in the browser because T-Pot uses a self-signed 
certificate. You can proceed by clicking “Advanced → Proceed anyway.

![26](https://github.com/user-attachments/assets/0984dd20-3612-4382-bfa3-066f1c5a39ca)

## 📊 What You See on the Attack Map

The T-Pot Attack Map provides a real-time visual representation of all the attacks targeting the honeypot. Here’s what it shows:

### 🗺️ Your Honeypot’s Location

As you can see in the image, the **pink pin** indicates my honeypot’s geolocation in **India** (`13.204.67.53` hosted on `ip-172-31-5-22`).

### 🌐 Top Hits by IP & Country

The map displays live data about incoming attacks, including:

- Source IP addresses  
- Country of origin (Germany, China, USA, Vietnam, etc.)  
- Type of honeypot or service being targeted (like FTP, SSH, TELNET)  
- The total number of hits  

### ⏱️ Last 1 Minute / Hour / 24 Hours Stats

At the top, you’ll notice counters showing how many attacks were observed in:

- The last 1 minute  
- The last 1 hour  
- The last 24 hours  

![27](https://github.com/user-attachments/assets/def60a2b-446a-4d0d-8b6b-44481c723603)

go to the dashboard click on kibana

![28](https://github.com/user-attachments/assets/a2eb1aa6-17fb-4ee0-b29b-b98b84da9389)

![29](https://github.com/user-attachments/assets/8e155ca1-0fca-47c6-aac5-147595b98f44)

## 2. Kibana Dashboard Summary

This dashboard is built on **Elasticsearch + Kibana** and displays visual analytics of honeypot data.

### 📈 Total Honeypot Attacks:
- 16 total attacks in the last 24 hours  
- 13 from **Honeytrap**  
- 3 from **Cowrie**  

### ⏳ Attacks Over Time:
- Histograms show attack frequency and source IP variation.  
- Attacks occurred throughout the day with spikes in the evening.  

### 🌍 Dynamic Attack Map:
- Visualizes live attack points globally.  
- Most intense attacks appear in Asia and Europe.  

---

## 3. Attack Types and Sources

### 👥 Types of Attackers:
- Known attackers and mass scanners are both present.  
- Pie charts represent proportions of attacker types and honeypot services triggered.  

### 🎯 Targeted Platforms:
- Attackers are targeting:  
  - Linux kernels  
  - Solaris  
  - Windows NT  

### 🌐 Top Attacking Countries:
- Germany  
- United States  
- Brazil  
- China  
- South Korea  

Each country is associated with specific ports (like 4103, 8080, 24625) that were scanned or attacked.

---

## 4. Suricata IDS Alerts

T-Pot uses **Suricata** to generate alerts based on attack signatures.

### 🔍 Top Suricata Signatures:
- ET DROP Dshield Block Listed Source  
- ET INFO SSH session in progress  
- ET SCAN NMAP -sS  
- ET INFO Inbound HTTP CONNECT Attempt on Off-Port  

These show attempts of Nmap scans, SSH brute force, and malicious HTTP traffic.

### 🛡️ Suricata CVEs:
- No CVEs have been identified yet in the logs, meaning no known vulnerabilities have been exploited during these attacks (as of now).

---

## 5. Attacker Information

### 🚩 Top Attacker ASNs:
- Alibaba US  
- Microsoft-C  
- Chinanet  
- Korea Telecom  
- DigitalOcean  
- These are the hosting providers or networks from which attacks originated.

### 📍 Top Source IPs:
- 8.209.96.38  
- 183.17.236.110  
- 125.136.231.2  

These IPs repeatedly attacked your honeypot and triggered Suricata alerts.

![30](https://github.com/user-attachments/assets/90a821a6-b990-43b6-895d-cdf6cfd5fe33)

![31](https://github.com/user-attachments/assets/c6f51b43-cb53-4855-b317-dc6b261c2c0a)

## 🌐 Geo-Map Insights (Visual Map)

- The **white and red lines** on the map represent attack traces.  
- The animated paths (from **Asia, Europe, and North America**) reflect incoming intrusion attempts.  
- The **magenta pin** in India shows your server location (where T-Pot is running).  
- Arrows from **USA, China, UK, and Germany** show attackers scanning or interacting with your honeypot.

---

## 📝 Conclusion: Increased Attack Surface Visibility

Compared to earlier, both the attack volume and targeted services have increased. The **Cowrie honeypot** is effectively detecting **SSH** and **TELNET**-based attacks.  

Attackers from multiple countries are interacting with the honeypot, which indicates that your server is publicly visible on the internet and is attracting bots and automated scanners. The Cowrie honeypot is effectively detecting SSH and TELNET-based attacks.

![33](https://github.com/user-attachments/assets/dcfc095e-0a22-4986-b80b-fd4b28e3c6bd)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


# Ethical-Phishing-Simulation-Platform - By Gourav Niroula (Project 2)

An open-source platform designed for cybersecurity awareness training through realistic, ethical phishing simulations. This tool helps organizations educate employees, test resilience to social engineering attacks, and improve overall security posture — without compromising user privacy or trust.

---

## Sample Link

This is the link of sample:  
`phishing_pot/email/sample-1009.eml` at main · rf-peixoto/phishing_pot  
A collection of phishing samples for researchers and detection developers.  
[phishing_pot/email/sample-1009.eml at main](https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-1009.eml)

---

## Phishing Email Analysis: Sample-1009.eml

### 1. Email Header Analysis

**Tool used:** MXToolbox Header Analyzer

**To analyze the email header:**

- Open the email in Gmail.
- Click on the three dots (⋮) → "Show Original".
- Copy the full header and paste it into the MXToolbox tool.

 ![a](https://github.com/user-attachments/assets/8e325e64-c1a7-432e-89c0-6b95b50bc5d7)

**Key Findings:**

- Blacklisted IP Address: The sending server appears on known blacklists.
- Authentication Failures: SPF/DKIM/DMARC checks failed.
- Received Paths: Indicate email was relayed through suspicious or spoofed sources.

![b](https://github.com/user-attachments/assets/c055d20b-fb39-459f-bc3c-3e8d567a52e0)

![c](https://github.com/user-attachments/assets/cffa30c6-6119-448e-8cc2-eeb3d83e4883)

**Sample link for header analysis:**  
[https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=9331f3c8-e3c9-4723-b961-c9abbfe5fe23](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=9331f3c8-e3c9-4723-b961-c9abbfe5fe23)  

You can see this IP is blacklisted.

![d](https://github.com/user-attachments/assets/cb38be62-c201-4312-a332-bf0679edd4aa)

---

### 2. Identify Suspicious Links or Attachments

- To identify suspicious links, first copy the link and go to VirusTotal and paste it.  
- Suspicious link is:  
`http://ecs-49-0-248-79.compute.hwclouds-dns.com/`  
- You can easily identify this as suspicious.

---

### 3. Look for Urgent or Threatening Language in the Email Body


If you read this email, you can see the following:


> You are expected to call DHL office +1(318)901–5153 immediately you receive this message because Bank of America (BOA) has finally released your compensation fund of $6,400,000.00 million USD and it has been programmed into an ATM visa debit card.  
> Right now your ATM card parcel is in DHL office waiting for your address of where to deliver it.

---

### 4. Note Any Mismatched URLs (Hover to See Real Link)

There are no clickable URLs in the email, but if there were, it’s important to hover over any links to check if the displayed text matches the actual URL. In phishing emails, attackers often use mismatched URLs to trick users into clicking malicious sites that look legitimate. Always verify the real destination before clicking.

![e](https://github.com/user-attachments/assets/0e39de24-1bae-4e76-a729-1b550f616713)

Always verify the real destination before clicking.

![f](https://github.com/user-attachments/assets/02e14ac7-d181-4413-9063-7b8464b68e0f)


---

### 5. Verify Presence of Spelling or Grammar Errors

This mail contains many spelling and grammatical errors:

- The message contains several errors, including incorrect number formats (e.g., “$6,400,000.00 million” is wrong).
- Awkward greetings (“Greetings Dear,” should be “Dear [Name],”).
- Missing articles (“in DHL office” should be “in the DHL office”).
- Run-on sentences without proper punctuation.
- Phrases like “Best Regard” should be plural (“Best Regards”).
- Closings like “Yours In Service” are not standard and should be replaced with “Sincerely” or “Yours sincerely.”
- Proper formatting for lists and clear sentence structure will make the message more professional and easier to read.

---

### 6. Summarize Phishing Traits Found in the Email

**Phishing Traits in the Email:**

- Unexpected large money offer: Claims of $6.4 million compensation out of nowhere.
- Urgency and pressure: Asking to call immediately.
- Suspicious contact details: Uses a generic Gmail address instead of an official company email.
- Poor grammar and formatting: Shows unprofessional language and mistakes.
- Request for personal information: Asks for name, address, and phone number.
- Unverified sender: Email headers show inconsistent and suspicious sources.
- Too good to be true: Offers huge money with little explanation.

---

### 7. Suspicious Link Detection

**Detected URL:**  
`http://ecs-49-0-248-79.compute.hwclouds-dns.com/`

**Tool used:** VirusTotal

- Submitted the URL and identified it as malicious.
- Domain mimics legitimate cloud infrastructure to avoid detection.

---

### 8. Phishing Red Flags

**Phishing Traits Found:**

- Unexpected large money offer: Claims of $6.4M USD as "compensation".
- Urgency & pressure: "Call immediately" message to trick victims into acting fast.
- Suspicious email address: Uses free email service (Gmail) instead of official domain.
- Requests sensitive information: Name, address, and phone number.
- Poor grammar & spelling: Numerous errors and awkward sentence structures.
- Suspicious links: Redirect to untrusted domain names.
- Unverified sender: Email headers suggest forged or spoofed addresses.

---

### 9. Sample Email Body (Excerpt)

Greetings Dear,

You are expected to call DHL office +1(318)901–5153 immediately you receive this message because Bank of America (BOA) has finally released your compensation fund of $6,400,000.00 million USD and it has been programmed into an ATM visa debit card.

Right now your ATM card parcel is in DHL office waiting for your address of where to deliver it.


**Issues:**

- "$6,400,000.00 million" is a nonsensical amount.
- "in DHL office" should be "in the DHL office".
- Closing salutation like “Yours In Service” is non-standard.

---

### 10. Email Authenticity Issues

- **Mismatched Headers:**  
  From field claims to be from an official source, but headers show it was sent from a suspicious server/IP.

- **Authentication Failures:**  
  - SPF: Fail  
  - DKIM: Fail  
  - DMARC: Fail

---

### 11. Summary of Key Phishing Indicators

| Indicator          | Details                       |
|--------------------|------------------------------|
| Unexpected reward   | Promises $6.4M compensation   |
| Urgency            | "Call immediately" tactic     |
| Suspicious sender  | Free Gmail used               |
| Malicious link     | Fake cloud domain             |
| Grammar errors     | Numerous throughout email    |
| Data request       | Wants personal info           |
| Header mismatch    | Email source spoofed          |

---

## Reference

- Original Sample: sample-1009.eml  
- Header Analysis: MXToolbox Result

---

## Educational Purpose

This project is part of a Cybersecurity Awareness & Threat Detection series. It demonstrates real-world phishing tactics and how to analyze, detect, and prevent such threats.  

**This is for research and educational purposes only. Do not engage with the email contents.**


Finished...
