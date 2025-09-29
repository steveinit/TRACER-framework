# TRACER
TRACER is a acronym, a punny mnemonic harkening to phone call tracing or maybe a tracer bullet, I dunno. It sounds cool. The TRACER Framework is a 6 Pillar system for enabling, conducting, and utilizing network derived cyberthreat/cyberattack intelligence. The framework begins with the work that should be done (hopefully) before the cyber incident, provides guidance on detecting the incident before documenting and communicating during the _the incident_. Finally, the framework moves into mitigating the threat and refining processes and controls. You can read about it below, though as of uploading this to Github, I'm not ready to put all my writing out there.

tracer.py was once just a text-based markdown form, a young little _.md_. The I wrote some bad python until it become a neat little text file appender I used to track a cyber incident beginning with a threat packet's source and destination IP, then literally tracing the network manually and adding in lines for any network appliances and their network intelligence. It made lines that looked like this:

DDOS 202504017:0623: 8.8.8.8->(Ge0/0{100.0.0.1[WANRouterA]192.168.0.1}Ge0/1)->(Ge0/0/0{VLAN100[Catalyst3850_lab]VLAN192}Ge0/0/1)->(192.168.0.27[webGoat_lab])

It's super ugly. I didn't check who own that public IP, but it's not mine.
tracer.py is what happened when I fed my python into Claude Opus 4.1, and it laughed in my face. Claude and I have been fighting now for a few days, but here is the prototype. You run it, it builds the documentation.

Oh, and I built it mostly with python built-ins. If anyone wants to collab, let's try to keep it that way. I work in the cyber vendor space, and boy do some orgs have crazy rules about importing new python libs.

## Example Output

Here's an example of TRACER in action, analyzing a SQL injection attack path:

```
============================================================
TRACER Framework - Network Path Analysis Tool
============================================================

--- INITIAL DETECTION ---
Threat type detected (e.g., SQL Injection, Malware C2): SQL Injection
Source IP address: 192.168.1.100
Destination IP address: 10.0.0.50

Detected: SQL Injection
  Source: 192.168.1.100
  Destination: 10.0.0.50

--- ENRICHMENT LEVEL 1 ---
============================================================
CURRENT NETWORK PATH
============================================================
SOURCE: 192.168.1.100
  [1] <-- Insert Point
    ↓
DESTINATION: 10.0.0.50

Your choice: 1
--- ADD NETWORK ELEMENT ---
Network element type: firewall
Firewall name/identifier: ASA-5525
Is this direct traversal or lateral movement? (direct/lateral): direct

--- ASA-5525 INFORMATION ---
Information type: source_interface
source_interface: GigabitEthernet0/1

Add destination-specific information for this element? (y/n): y
Information type: destination_interface
destination_interface: GigabitEthernet0/2
Information type: ACL_rule
ACL_rule: permit tcp any host 10.0.0.50 eq 80

--- ENRICHMENT LEVEL 2 ---
============================================================
CURRENT NETWORK PATH
============================================================
SOURCE: 192.168.1.100
  [1] <-- Insert Point
    ↓
  ASA-5525 (FIREWALL) - Direct Traversal
      • source_interface: GigabitEthernet0/1
  [2] <-- Insert Point
    ↓
DESTINATION: 10.0.0.50

Your choice: 2
--- ADD NETWORK ELEMENT ---
Network element type: switch
Switch name/identifier: Catalyst-3850
Is this direct traversal or lateral movement? (direct/lateral): direct

--- CATALYST-3850 INFORMATION ---
Information type: source_port
source_port: Gi1/0/24
Information type: CAM_entry
CAM_entry: 0025.64FF.EE12

Add destination-specific information for this element? (y/n): y
Information type: destination_port
destination_port: Gi1/0/12
Information type: VLAN
VLAN: 100

Your choice: done

============================================================
TRACER ANALYSIS REPORT
============================================================

Case ID: CASE_20250929_125453
Threat Type: SQL Injection
Analysis Timestamp: 2025-09-29T12:54:53.653779
Network Elements Analyzed: 2

--- COMPLETE NETWORK PATH ---
SOURCE: 192.168.1.100
    ↓
  ASA-5525 (FIREWALL) - Direct Traversal
      Source → source_interface: GigabitEthernet0/1
      Dest → destination_interface: GigabitEthernet0/2
      Dest → ACL_rule: permit tcp any host 10.0.0.50 eq 80
    ↓
  Catalyst-3850 (SWITCH) - Direct Traversal
      Source → source_port: Gi1/0/24
      Source → CAM_entry: 0025.64FF.EE12
      Dest → destination_port: Gi1/0/12
      Dest → VLAN: 100
    ↓
DESTINATION: 10.0.0.50

--- ANALYSIS SUMMARY ---
Direct Traversals: 2
Lateral Movements: 0
Pivot Points: 0

Save analysis to JSON file? (y/n): y
Analysis saved to tracer_analysis_CASE_20250929_125453.json
Case data automatically saved to: tracer_database.json

============================================================
TRACER Analysis Complete
Trust → Recognize → Analyze → Communicate → Engage → Refine
============================================================

# The TRACER Framework
- TRUST: Network Appliance Integrity (Pre-Incident)
	- Can you trust your Routers, Switches, Firewalls, Proxies, Load Balancers, IPS/IDS, NDRs have not been tampered with during an attack?
		- This is simple in practice but an administrative pain, and it's fundamental to the rest of the network forensics process. Harden your network appliances. If your switch logs can be tampered with by an attacker, they are worse than forensically useless: They have become part of the attack itself.
	- Do you/your team have the competence to derive network forensic intelligence from network technologies?
- RECOGNIZE: Threat Identification (Incident Starts)
	- Can you catch the threat? (Discover)
		- Do you have network-based threat detection systems in place. At minimum, Next-Gen Firewall, WAN Edge IDS, and an East-West NDR around business applications are required.
	- Can you define the nature of the Threat's traffic so that it can be caught initially or in the future? (Signature/Fingerprinting/Etc)
		- Can you update these systems with the latest threat profile and create new profiles for emerging threats?
- ANALYZE: Threat Traffic Mapping (Active Threat Investigation)
	- Can you then map the network traffic caused by the threat directly through C&C/recon/exploit/exfil and traversal, logically and chronologically?
	- Leverage the Source->Destination Iterative Model
	- This process may continue as additional intelligence is gathered and assessed well after the successful ENGAGE mitigation.
- COMMUNICATE: Threat Knowledge Collaboration and Documentation
	- Can you work with other experts outside of your competence edge, silo, or separation of duties? Most attacks are not exclusively network attacks. The network forensics expert must be able to collaborate with other cybersecurity experts, systems teams, and sometimes legal and leadership.
	- Can you document your findings?
- ENGAGE: Threat Response
	- Can you articulate network controls to mitigate/thwart the active threat? This is why a network forensics expert must understand network and network service technologies from the endpoint NIC to the edge.
	- Can you communicate your finding to influence Mitigation on non-network appliance/technology systems?
- REFINE: Threat Remediation and Services Restoration
	- Can you communicate your findings to implement detective and preventative controls for a recurrent or like threat beyond the mitigating control employed at need? Refining should include the analysis of the whole attack and mitigating controls along the attack chain. Anyone can mitigate and attack by implementing a firewall ACL for the source, but defense in depth provides deeper protection for dynamic/polymorphic attacks.
	- Can you validate the controls are effective?
