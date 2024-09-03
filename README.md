# Industrial-Cybersecurity-

Introduction
In today's highly connected world, network security is paramount. Protecting organizational data and ensuring
secure communication within and outside the network is crucial. This report details the setup and configuration
of a Demilitarized Zone (DMZ) using the pfSense firewall. The project highlights key configurations, including
network segmentation, security policies, and services implemented to enhance the security posture of the
network.
pfSense, an open-source firewall and router software, offers robust features for managing network traffic and
security. By deploying a DMZ, we create an additional layer of security, isolating critical systems from potential
threats while allowing necessary external access.

Understanding DMZ (Demilitarized Zone)
A DMZ, or Demilitarized Zone, is a physical or logical subnetwork that contains and exposes an organization's
external-facing services to an untrusted network, usually the Internet. The primary purpose of a DMZ is to add
an additional layer of security to an organization's internal network, protecting it from external attacks. By
isolating the external services, the internal network remains secure even if the DMZ is compromised.

DMZ Policies and Rules

Blocking All Ports by Default
To enhance security, all incoming and outgoing ports within the DMZ are blocked by default. This ensures that
no unauthorized traffic can traverse the DMZ without explicit permission.

Allowing Specific Ports

Specific ports are allowed to facilitate necessary communication:

• HTTP (Port 80): For web traffic.

• HTTPS (Port 443): For secure web traffic.

• NTP (Port 123): For network time protocol synchronization.

• STUN (Port 3478): For NAT traversal in VoIP

Implementation of IDP/IPS Using Snort

Snort, an open-source intrusion detection and prevention system, is configured to monitor and
analyze network traffic for signs of malicious activity. This adds a layer of real-time threat
detection and response.

Ad Blocking with PFNG

Configuring PFNG for Ad Blocking

PFNG (pfBlocker-NG) is configured to block unwanted advertisements and malicious domains. This enhances
user experience and reduces network bandwidth usage.
Benefits of Ad Blocking

• Improved network performance.
• Enhanced security by blocking malicious ad domains.
• Reduced exposure to malware and phishing attacks.

Network Segmentation and Policies

Separation of DMZ from Enterprise and Industrial Networks

Network segmentation is crucial for minimizing the attack surface. Separate policies are created to ensure that
the DMZ cannot directly communicate with the enterprise and industrial networks, thus containing potential
threats within the DMZ.

Assigning Specific Ports for pfSense Login
To further secure the management interface, a specific port is assigned for pfSense login, reducing the risk of
unauthorized access.

Static Routing and DNS Configuration
Importance of Static Routing
Static routes are configured to control the path that network traffic takes, ensuring optimal and secure routing of
data.

Configuring DNS Servers
The DNS servers 8.8.8.8 (Google) and 1.1.1.1 (Cloudflare) are configured to provide reliable and fast domain
name resolution services.

Watchdog Service and DHCP Configuration
Utilizing the Watchdog Service
The watchdog service is enabled to monitor system processes and automatically restart them if they fail,
ensuring continuous network availability.

Setting Up DHCP
The DHCP server is configured to dynamically


![image](https://github.com/user-attachments/assets/23bdc17c-d0de-49aa-ba9f-3b599629bb3a)

Pfsense Firewall-DMZ 

![image](https://github.com/user-attachments/assets/d2884bb1-b210-471b-99bf-c5cbac11dcb2)

DMZ Policies 

![image](https://github.com/user-attachments/assets/664e5525-bcc9-40db-bfa4-a5367c074dad)

Enterprise Zone

Introduction

Ensuring robust network security involves the meticulous configuration of different network zones, each with
specific policies tailored to its function. In addition to the Demilitarized Zone (DMZ), the Enterprise Zone plays
a crucial role in securing sensitive organizational data and communications. This report elaborates on the
configurations and policies applied to the Enterprise Zone using pfSense, and details the WAN interface
configurations to block unwanted traffic.

Enterprise Zone Configuration

Blocking All Ports by Default

To maintain a high level of security within the Enterprise Zone, all ports are blocked by
default. This policy ensures that no unauthorized traffic can enter or exit the network, thereby
protecting sensitive enterprise data from external threats.

Allowing Specific Ports

For necessary communication and services, the following ports are explicitly allowed:
• HTTPS (Port 443): Ensures secure web communication.
• DNS (Port 53): Facilitates domain name resolution.
• NTP (Port 123): Synchronizes the network time protocol.
• STUN (Port 3478): Supports NAT traversal for VoIP services.

By selectively allowing these ports, we enable essential services while maintaining a secure environment.
Network Segmentation

To further enhance security, the Enterprise Zone is segregated from the DMZ and Industrial Zone. This
segmentation prevents any direct communication between these zones, thereby containing potential threats
within their respective boundaries. The policies ensure that data and communications within the Enterprise Zone
are insulated from other network segments, reducing the risk of cross-network breaches.
Watchdog Service

The Watchdog service is configured in the Enterprise Zone to monitor critical processes. It automatically
restarts any failed processes, ensuring continuous network availability and reducing downtime. This is vital for
maintaining the operational integrity of enterprise services.

Intrusion Detection and Prevention

Snort, a robust intrusion detection and prevention system, is deployed in the Enterprise Zone. Snort monitors
network traffic in real-time for signs of malicious activity and takes proactive measures to prevent potential
attacks. This adds an essential layer of defense against cyber threats.

DHCP Configuration

Dynamic Host Configuration Protocol (DHCP) is enabled in the Enterprise Zone to simplify
IP address management. DHCP automatically assigns IP addresses to devices within the
network, ensuring efficient network management and device connectivity.

VPN Tunneling with WireGuard

To secure remote connections, WireGuard VPN tunneling is implemented in the Enterprise Zone. Full tunneling
is applied to route all traffic through the VPN, ensuring that all data is encrypted and protected. This
configuration, while enhancing security, has the drawback of potentially reducing internet speed due to the
overhead of encryption.

WAN Interface Configuration

Blocking Private and Bogon Networks

To protect the internal network from spoofed or malicious traffic, the following policies are applied to the WAN
interface:

• Blocking Private Networks: Prevents traffic from IP ranges that are designated for private use but
should not appear on the public internet.
• Blocking Bogon Networks: Prevents traffic from invalid or unallocated IP ranges that could be used
for malicious purposes.

These policies help in reducing the attack surface and preventing illegitimate traffic from reaching the internal
network.

Conclusion
The meticulous configuration of the Enterprise Zone and the application of strict policies on the WAN interface
are crucial steps in fortifying network security. By blocking unnecessary ports, segmenting networks, and
implementing advanced security measures such as Snort and WireGuard, we significantly enhance the security
posture of the enterprise network. The combined use of these strategies ensures that sensitive data and
communications are well-protected against potential threats, while also maintaining operational efficiency and
network integrity.

Zone 2 Enterprise Network

![image](https://github.com/user-attachments/assets/3bcd3db0-0403-4c82-abd7-f7a18421bd02)

Enterprise Policies 

![image](https://github.com/user-attachments/assets/c1e4b3a9-3a0d-483f-82dc-ed021495d5c0)

Industrial Zone


Introduction


The Industrial Zone within a network requires stringent security measures to protect critical infrastructure and
ensure operational continuity. This report outlines the detailed configuration and policies applied to the
Industrial Zone using pfSense firewall. The setup includes comprehensive security rules, network segmentation,
traffic monitoring, and redundancy measures to maintain a secure and resilient network environment.

WAN Interface Configuration

Blocking Private and Bogon Networks

To safeguard the Industrial Zone from unauthorized access and potential attacks, the WAN interface is
configured to block:

• Private Networks: Prevents traffic from IP ranges designated for private use, which should not appear
on the public internet.
• Bogon Networks: Blocks traffic from invalid or unallocated IP ranges, reducing the risk of malicious
activity.

These measures ensure that only legitimate traffic reaches the Industrial Zone, enhancing overall network
security.

LAN Interface Configuration

Blocking All Ports

By default, all ports on the LAN interface are blocked to prevent unauthorized access and mitigate potential
threats. This strict policy ensures that no unintended traffic can enter or exit the Industrial Zone, maintaining a
secure perimeter.

Blocking Social Media Sites
To maintain productivity and reduce the risk of data leakage, social media sites are blocked using Fully
Qualified Domain Names (FQDNs). This policy helps in preventing unauthorized access to these platforms
within the Industrial Zone.

Network Segmentation
The Industrial Zone is segregated from other network segments to enhance security and containment. This
separation ensures that the Industrial Zone operates independently, preventing direct communication with the
DMZ and Enterprise Zones and reducing the risk of lateral movement by potential attackers.

Allowing Specific Ports
For necessary communication and remote management, the following ports are allowed:
• DNS (Port 53): Enables domain name resolution.
• HTTPS (Port 443): Ensures secure web communication.
• RDP (Port 3389): Allows remote desktop access.
• SSH (Port 22): Enables secure shell access for remote management.
These ports are essential for maintaining connectivity and managing industrial devices
securely.

DHCP Configuration

Dynamic Host Configuration Protocol (DHCP) is enabled to automate IP address assignment for devices within
the Industrial Zone. This simplifies network management and ensures efficient device connectivity.

Intrusion Detection and Prevention

Snort, a robust Intrusion Detection and Prevention System (IDP/IPS), is configured to monitor and analyze
network traffic for signs of malicious activity. Snort enhances security by detecting and responding to potential
threats in real-time.

Watchdog Service

The Watchdog service is deployed to monitor critical processes and ensure continuous network availability. If
any process fails, the Watchdog automatically restarts it, minimizing downtime and maintaining operational
integrity.

Backup Interface

A backup interface is configured to provide redundancy. In case the primary interface fails, the network can
switch to the backup interface, ensuring uninterrupted connectivity and enhancing network resilience.
Ad Blocking with PFNG

PFNG (pfBlocker-NG) is configured to block unwanted advertisements and malicious domains. This improves
network performance, enhances user experience, and reduces exposure to potential threats from malicious ads.
Blocking Torrent Sites

Torrent sites are blocked to prevent unauthorized file sharing and reduce the risk of malware. This policy
ensures that the network bandwidth is used efficiently and securely.
Monitoring and Logging

All allowed and blocked policies are configured in monitor mode, and detailed logs are maintained. This
comprehensive logging enables continuous monitoring and analysis of  network traffic, providing insights into
potential security incidents and ensuring compliance with security policies.

Zone 3 Industrial Network 

![image](https://github.com/user-attachments/assets/046d6bce-65fc-40e7-b3ad-7cfb6500cd89)


Policies 

![image](https://github.com/user-attachments/assets/51b6d845-859d-4975-aca4-18fe2552dfa1)

Security Onion Configuration in Industrial Network


Introduction

Security Onion is an open-source platform for threat hunting, enterprise security monitoring,
and log management. In the context of the Industrial Network, Security Onion provides
comprehensive monitoring and analysis capabilities to ensure the security and integrity of
industrial systems. This report outlines the basic policies and configuration of Security Onion
within the Industrial Network, highlighting its role in monitoring and protecting connected
clients.

Security Onion Overview

Security Onion integrates a suite of tools designed for network security monitoring, including
intrusion detection, log management, and network visibility. By deploying Security Onion in
the Industrial Network, organizations can effectively monitor network traffic, detect
anomalies, and respond to potential threats.

Basic Configuration of Security Onion

Deployment

Security Onion is deployed on a dedicated server within the Industrial Network. This
deployment ensures that the platform has the necessary resources and network access to
perform comprehensive monitoring and analysis of all connected clients.

Network Interfaces
Security Onion is configured to monitor traffic on the industrial interfaces. It captures and
analyzes data from these interfaces to identify potential security incidents. The configuration
includes:

• Network Tap or Span Port: Ensures that all traffic to and from industrial devices is
captured.
• Monitoring Interfaces: Dedicated interfaces on the Security Onion server for traffic
analysis.

Intrusion Detection and Prevention

Security Onion integrates popular intrusion detection systems (IDS) like Suricata and Zeek
(formerly known as Bro). These systems are configured to analyze network traffic for signs
of malicious activity:

• Suricata: Provides real-time intrusion detection and prevention, alerting on
suspicious activities.

• Zeek: Offers in-depth network analysis, providing detailed logs of network
transactions.

Log Management and Analysis

The Elastic Stack (Elasticsearch, Logstash, and Kibana) is configured within Security Onion
for log management and analysis:

• Elasticsearch: Stores logs and security events for efficient querying and analysis.
• Logstash: Processes and transforms logs before storing them in Elasticsearch.
• Kibana: Provides a web interface for visualizing and exploring security data.
Basic Policies

Security Onion is configured with basic policies to ensure effective monitoring and threat
detection:

• Baseline Traffic Analysis: Establishes a baseline of normal network traffic to detect
anomalies.

• Alert Thresholds: Configured to generate alerts for suspicious activities based on
predefined rules.

• Log Retention Policies: Ensures logs are retained for a specified period for historical
analysis and compliance.

Monitoring and Alerts

The Security Onion setup includes dashboards and alerting mechanisms to provide real-time
visibility into the Industrial Network's security status:

• Dashboards: Preconfigured dashboards in Kibana offer insights into network
activity, security events, and potential threats.

• Alerting: Configured to send alerts via email or other notification systems when
suspicious activities are detected.

Threat Hunting and Incident Response

Security Onion facilitates proactive threat hunting and incident response:

• Threat Hunting: Analysts can query and investigate network traffic and logs to
identify potential threats.

• Incident Response: Provides tools and data necessary for investigating and
responding to security incidents, including packet captures and log analysis.
Benefits of Security Onion in Industrial Network

Deploying Security Onion within the Industrial Network offers several advantages:
• Enhanced Visibility: Comprehensive monitoring of network traffic and connected
clients.

• Early Detection: Real-time intrusion detection helps in identifying and mitigating
threats promptly.

• Detailed Analysis: In-depth logs and network data facilitate thorough investigations.

• Proactive Security: Supports threat hunting and proactive identification of
vulnerabilities.

![image](https://github.com/user-attachments/assets/a542cff1-3f0b-46f3-8674-e7960e2c735b)


Conclusion

In this project, we successfully designed and implemented a comprehensive industrial network using Proxmox. The network was structured with robust security measures, including the deployment of multiple pfSense firewalls. Key features such as VLANs, OSPF routing, and advanced firewall configurations with Snort IPS/IDS, pfBlockerNG, and WireGuard VPN were integrated to create a highly secure and segmented network.

The network was meticulously segmented into DMZ, Enterprise, and Industrial zones, each protected by dedicated firewalls to ensure a layered security approach. The inclusion of Security Onion provided enhanced monitoring and threat detection capabilities, ensuring real-time visibility into network activities.

After the network setup, a red team conducted white-box testing to evaluate its security. The testing revealed no significant vulnerabilities, demonstrating the effectiveness of the security measures implemented. The only exception was a few open ports, which were continuously monitored to prevent any potential exploitation. This rigorous testing and monitoring affirm that the network is well-protected against external threats while maintaining operational efficiency.

Note: Unfortunately, I don't have the source file for this project because I built it on Proxmox.







