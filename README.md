# HoneyPot-Server-to-Detect-Attack-Patterns
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

How Honeypots Work: Real Attacks, Safe Systems, and the T-Pot Advantage
Inside the Trap: Understanding Honeypots with Real-World Examples

Using T-Pot to Attract and Analyze Real Cyber Attacks — A Beginner’s Guide

Deploying T-Pot Honeypot Safely on Ubuntu: Real Threats in a Controlled Lab

Introduction
➤ What is a honeypot? Why is it used in cybersecurity?
What is T-Pot and How Does It Work?
➤ Explain multi-honeypot framework and logging with ELK stack.
Can Hackers Really Attack My System?
➤ Clarify doubts about real vs virtual attacks.
Real-World Analogy: Honeypot is a Fake Shop
➤ Use your example here (see below).
Running T-Pot on a Windows System Safely
➤ Explain VirtualBox + Ubuntu method to isolate real machine.
Why Do Companies Run T-Pot 24/7?
➤ SOC / Threat Intelligence / Logging / Alerting reasons.
Conclusion: Safe Experimentation, Real Threat Insight
➤ Honeypots are powerful tools for both learning and real defense.
Real-World Analogy: Honeypot is a Fake Shop
Imagine setting up a fake shop inside your house, designed to look real from the outside. You place attractive signs, open the door halfway, and even display fake items in the window.

Outsiders walking by — especially those looking to steal — see this and try to break in. But here’s the trick: the fake shop leads nowhere. It’s not connected to the rest of your home.

It’s just a setup to lure potential thieves, monitor what they do, and collect their methods — all without putting your real home at risk.

That’s exactly how a honeypot works in cybersecurity. It looks like a vulnerable system to attackers, but it’s isolated from your real machines. While attackers believe they’re hacking something valuable, you’re actually recording their every move.

Launching a New Instance on ECE (Elastic Compute Environment)
To deploy the T-Pot honeypot safely on a cloud machine, I started by launching a new virtual instance using my ECE cloud panel.

Step-by-Step Instance Creation
11. Clicked on “Launch Instance”
From the ECE dashboard, I clicked on the “Launch Instance” button to begin creating a new virtual server.

![2](https://github.com/user-attachments/assets/97e32146-379a-42dc-bb25-ade075683f55)

2.Selected the Operating System: Ubuntu 
In the system configuration section, I chose Ubuntu as the operating system since T-Pot is 
designed to run on Ubuntu. 

![3](https://github.com/user-attachments/assets/31ff1a37-e05f-4108-a70f-0abdeea71cfc)

3.Set the Storage Size to 128 GB 
I allocated 128 GB of disk space to ensure there is enough room for the honeypot tools, logs, 
and dashboards (like Kibana and ELK stack data). 

![4](https://github.com/user-attachments/assets/a3d33a27-c53c-453c-856d-5077e4595fc6)

4.Chose a IP Address 
I selected a my IP address for the instance so that it could be accessible over the internet — 
allowing real-world attackers to reach the honeypot services exposed by T-Pot.v 

![5](https://github.com/user-attachments/assets/bcd61ee1-4b20-45c5-bc95-ffa19c828b47)

5.Generated a New SSH Key Pair 
I created a new key pair to securely access the virtual machine via SSH. This private key would 
be downloaded and used later for login.

![6](https://github.com/user-attachments/assets/39f9f98e-bf18-4a86-964c-72b640479aba)

6.Selected the Instance Type: t3.XLarge Tier 
I picked the t3.XLarge instance type to provide sufficient CPU and memory resources for 
running multiple honeypots and dashboards smoothly. 
7. Reviewed the Configuration 
After verifying all the selected options (OS, tier, storage, key, and IP), I proceeded to launch the 
instance. 
8. Clicked “Launch Instance” 
Finally, I clicked the “Launch Instance” button to deploy the virtual machine. Within a few 
minutes, the instance was up and running, ready for SSH access and T-Pot installation. 

![7](https://github.com/user-attachments/assets/babdb5a2-56b1-4117-8927-0bd9042ebee0)

![8](https://github.com/user-attachments/assets/a814daf7-d6e3-4085-98fe-04e41d4aed12)

After that go to the SSH client and copy the full command and go to the command prompt and 
terminal and paste it

![9](https://github.com/user-attachments/assets/df98c9e5-d84e-4aae-bbbc-8360dae68780)


SSH Login Command to Access the Instance: 
ssh -i "your-key.pem" ubuntu@<Public-IP> 

![10](https://github.com/user-attachments/assets/d33809c6-6f3a-4d89-9f4f-70d11e0dbde6)

![11](https://github.com/user-attachments/assets/a58f9c2a-fbf2-4b02-b4b8-fd42134f4991)

After that run this command; 
Sudo apt update

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

Once the T-Pot honeypot was successfully installed on my Ubuntu server, the next crucial step 
was to configure inbound rules to allow external traffic to reach the services provided by T-Pot. 
This is done through the Security Group or firewall settings in the cloud panel (ECE in my case). 
Here’s how I set it up: go to the ec2 instance select security and click on according to the arrow 

![18](https://github.com/user-attachments/assets/b5f91a03-4d94-4551-b4bf-607d91038e10)

Why I Opened Ports 64295 and 64297 in AWS Inbound Rules

After successfully installing T-Pot honeypot on my Ubuntu EC2 instance, I had to 
configure inbound rules to allow traffic to specific ports used by T-Pot’s services and 
dashboards. Here’s why these particular ports were chosen: 
Purpose of Each Port 
o Port 64295 (TCP) → This port is used by the T-Pot Web Cockpit (Admin UI). It 
provides an overview of the system status, uptime, and resource usage. It’s the 
main dashboard where I can monitor the honeypot’s performance and system 
health in real time. 
o Port 64297 (TCP) → This port is dedicated to the Kibana Dashboard, which is 
part of the ELK stack integrated with T-Pot. It visualizes the captured logs and 
attack data, showing rich visual analytics about the threats interacting with the 
honeypots. 
These ports are not standard (like port 80 or 22), which makes them less predictable and slightly 
more secure by default. 
two times click on add rules

![19](https://github.com/user-attachments/assets/db3c96e6-22f3-4491-a8bc-3558d028f9a7)

![20](https://github.com/user-attachments/assets/2a7ed9e8-f444-482d-b124-959ace29c3ac)

![21](https://github.com/user-attachments/assets/214f5762-207b-4db3-9513-a26f0e9fdd32)

Logging In After Firewall Setup 
Once the inbound rules were saved, I connected to the T-Pot server via SSH using this 
command: 
ssh -i "keys2.pem" ubuntu@ec2-13-204-67-53.ap-south-1.compute.amazonaws.com -p 64295 
Breakdown: 
o i "keys2.pem" → Path to the private key file for authentication 
o ubuntu@... → Default user and public IP/domain of my EC2 instance 
o p 64295 → Custom SSH port (T-Pot replaces the default port 22 with 64295 for 
added stealth) 

![22](https://github.com/user-attachments/assets/5ea85c6c-2c79-45d1-b2b4-b4bce744d737)

Go the ec2 instance and copy the ipv4 address and

![23](https://github.com/user-attachments/assets/b021211e-5de2-4b4b-8fe2-dfb8a139e08c)

run https://13.x.x.x:64297

![24](https://github.com/user-attachments/assets/2e8d766d-f8b6-4015-86ca-9334bebb848c)

After that login with username and password you created this before when we installing tpot

![25](https://github.com/user-attachments/assets/dcc6118d-c85b-4bf4-bde8-f6c7728316ba)

Real-Time Global Threat Monitoring via T-Pot Attack Map 
Once the honeypot was fully installed and the Kibana dashboard was accessible via port 64297, 
I opened the T-Pot Attack Map in the browser using the URL: 
https://<public-ip>:64297/map/ 
In my case: 
https://13.204.67.53:64297/map/ 
Note: You might see a security warning in the browser because T-Pot uses a self-signed 
certificate. You can proceed by clicking “Advanced → Proceed anyway.

![26](https://github.com/user-attachments/assets/0984dd20-3612-4382-bfa3-066f1c5a39ca)

What You See on the Attack Map 
The T-Pot Attack Map provides a real-time visual representation of all the attacks targeting the 
honeypot. Here’s what it shows: 
Your Honeypot’s Location 
As you can see in the image, the pink pin indicates my honeypot’s 
geolocation in India (13.204.67.53 hosted on ip-172-31-5-22). 
Top Hits by IP & Country 
The map displays live data about incoming attacks, including: 
o Source IP addresses 
o Country of origin (Germany, China, USA, Vietnam, etc.) 
o Type of honeypot or service being targeted (like FTP, SSH, TELNET) 
o The total number of hits 
Last 1 Minute / Hour / 24 Hours Stats 
At the top, you’ll notice counters showing how many attacks were observed in: 
o The last 1 minute 
o The last 1 hour 
o The last 24 hours 

![27](https://github.com/user-attachments/assets/def60a2b-446a-4d0d-8b6b-44481c723603)

go to the dashboard click on kibana

![28](https://github.com/user-attachments/assets/a2eb1aa6-17fb-4ee0-b29b-b98b84da9389)

![29](https://github.com/user-attachments/assets/8e155ca1-0fca-47c6-aac5-147595b98f44)

2. Kibana Dashboard Summary 
This dashboard is built on Elasticsearch + Kibana and displays visual analytics of honeypot data. 
Total Honeypot Attacks: 
o 16 total attacks in the last 24 hours. 
o 13 from Honeytrap 
o 3 from Cowrie 
Attacks Over Time: 
o You can see histograms showing attack frequency and source IP variation. 
o Attacks occurred throughout the day with spikes in the evening. 
Dynamic Attack Map: 
o Visualizes live attack points globally. 
o Most intense attacks appear in Asia and Europe. 
3. Attack Types and Sources 
Types of Attackers: 
o Known attackers and mass scanners are both present. 
o Pie charts represent proportions of attacker types and honeypot services 
triggered. 
Targeted Platforms: 
o Attackers are targeting: 
o Linux kernels 
o Solaris 
o Windows NT 
Top Attacking Countries: 
o Germany 
o United States 
o Brazil 
o China 
o South Korea 
Each country is associated with specific ports (like 4103, 8080, 24625) that were scanned or 
attacked. 
4. Suricata IDS Alerts 
T-Pot uses Suricata to generate alerts based on attack signatures. 
Top Suricata Signatures: 
o ET DROP Dshield Block Listed Source 
o ET INFO SSH session in progress 
o ET SCAN NMAP -sS 
o ET INFO Inbound HTTP CONNECT Attempt on Off-Port 
o These show attempts of Nmap scans, SSH brute force, and malicious HTTP 
traffic. 
Suricata CVEs: 
o No CVEs have been identified yet in the logs, meaning no known 
vulnerabilities have been exploited during these attacks (as of now). 
5. Attacker Information 
Top Attacker ASNs: 
o Alibaba US, Microsoft-C, Chinanet, Korea Telecom, DigitalOcean, etc. 
o These are the hosting providers or networks from which attacks originated. 
Top Source IPs: 
o 8.209.96.38 
o 183.17.236.110 
o 125.136.231.2 
o These IPs repeatedly attacked your honeypot and triggered Suricata alerts. 

![30](https://github.com/user-attachments/assets/90a821a6-b990-43b6-895d-cdf6cfd5fe33)

![31](https://github.com/user-attachments/assets/c6f51b43-cb53-4855-b317-dc6b261c2c0a)

Geo-Map Insights (Visual Map): 
o The white and red lines on the map represent attack traces. 
o The animated paths (from Asia, Europe, and North America) reflect incoming 
intrusion attempts. 
o The magenta pin in India shows your server location (where T-Pot is running). 
o Arrows from USA, China, UK, and Germany show attackers scanning or 
interacting with your honeypot. 
Conclusion: Increased Attack Surface Visibility 
Compared to earlier, both the attack volume and targeted services have increased. 
The Cowrie honeypot is effectively detecting SSH and TELNET-based attacks. 
Attackers from multiple countries are interacting with the honeypot, which indicates that your 
server is publicly visible on the internet and is attracting bots and automated scanners. The 
Cowrie honeypot is effectively detecting SSH and TELNET-based attacks.

![33](https://github.com/user-attachments/assets/dcfc095e-0a22-4986-b80b-fd4b28e3c6bd)


Finished...
