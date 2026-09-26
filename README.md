[README.md](https://github.com/user-attachments/files/32688068/README.md)
# Fortis-Enterprise-Network-Architecture
High-availability enterprise network infrastructure featuring HSRP L3 redundancy, ASA DMZ/Perimeter security, L2 hardening (DHCP Snooping/DAI), LACP EtherChannel, and remote branch IPSec VPN.

**Environment:** Simulated in Cisco Packet Tracer as a portfolio engineering for Fortis CyberSec S.A.
**Role:** Infrastructure Architect — design, configuration, security hardening, incident diagnosis, and remediation.

---

## 1. Executive Summary & Business Challenge

Fortis CyberSec S.A. required an infrastructure foundation capable of supporting **secure ERP database operations, remote branch connectivity, and strict data isolation between corporate and guest traffic — without any single point of failure.**

This translates into four concrete business risks the architecture had to eliminate:

| Business Risk | Consequence if Unaddressed | Architectural Answer |
|---|---|---|
| Gateway/router failure | ERP and database operations go offline; revenue-impacting downtime | Dual-router HSRP active/standby design |
| Flat, unsegmented network | A compromised guest device can reach servers/ERP data | VLAN segmentation + inter-VLAN ACLs |
| Uncontrolled perimeter exposure | Public-facing services become an entry point for attackers | ASA firewall with a dedicated DMZ and least-privilege ACLs |
| Isolated branch offices | No secure channel for data synchronization between sites | Site-to-site IPSec VPN |

The result is a layered, defense-in-depth network: **redundant Layer 3 gateways (HSRP)**, a **hardened Layer 2 access/distribution layer** (EtherChannel, Port Security, DHCP Snooping, Dynamic ARP Inspection), a **segmented perimeter** (ASA firewall + DMZ), and **centralized identity/logging services** (RADIUS/AAA, Syslog) — the same foundational patterns used to protect production ERP and business-database environments.

Every technical decision below is presented as: **Business/Technical Problem → Engineering Solution → Business Value Delivered.**

---

## 2. Architectural Problems, Engineering Solutions & Business Value

### 2.1 Zero-Downtime Gateway Availability (HSRP)

**Problem:** A single router acting as the default gateway for Admin, Voice, Guest, and Server VLANs is a single point of failure. If it fails, every VLAN — including the segment hosting database/ERP servers — loses its path to the network.

**Engineering Solution:** Two routers, **Fortis-GW1** and **Fortis-GW2**, were deployed as an **HSRP version 2 active/standby pair** across all four VLANs, each exposing a shared virtual gateway IP. GW1 is the active router (priority 110) with `preempt` enabled so it reliably reclaims the active role once restored.

```
interface GigabitEthernet0/0.10
 encapsulation dot1Q 10
 ip address 192.168.10.2 255.255.255.0
 ip helper-address 192.168.99.10
 standby version 2
 standby 10 ip 192.168.10.1
 standby 10 priority 110
 standby 10 preempt
 no shutdown
exit
```

A dedicated point-to-point heartbeat link (`10.0.0.0/30`) between GW1 and GW2 carries HSRP state independently of the main data path.

**Business Value Delivered:** the default gateway for every business VLAN — including the segment designed to host ERP/database services — is **architecturally protected against a single router outage**, without requiring any reconfiguration on end devices or servers during a failover event.

[INSERT SCREENSHOT: HSRP / routing verification]

### 2.2 Resilient Access-Distribution Layer (LACP EtherChannel + PVST+)

**Problem:** A single trunk link between the access switch and the core switch is both a bandwidth constraint and a failure point; a single blocked/broken link can isolate an entire floor or department from the rest of the network.

**Engineering Solution:** Switch-Core and Switch-Access are interconnected through a **2-member LACP EtherChannel (Port-Channel 1)**, load-balancing and providing link-level redundancy. **PVST+** is layered on top with Switch-Core as **Root Primary** and Switch-Access as **Root Secondary**, giving Spanning Tree a deterministic, loop-free topology with a known failover path.

```
interface range FastEthernet 0/11 - 12
 switchport mode trunk
 switchport trunk native vlan 99
 channel-group 1 mode active
 no shutdown
exit

interface Port-channel 1
 switchport mode trunk
 switchport trunk native vlan 99
exit
```

**Business Value Delivered:** aggregated bandwidth and link-level redundancy at the access-distribution boundary reduce the risk of localized outages disrupting user productivity or access to centralized services.

### 2.3 Data Isolation by Design (VLAN Segmentation)

**Problem:** Without segmentation, guest wireless traffic, VoIP, administrative workstations, and backend servers share the same broadcast domain — meaning a compromised guest laptop is one hop away from internal servers.

**Engineering Solution:** Four purpose-built VLANs enforce separation at Layer 2, reinforced by an **ACL on the router subinterface** that explicitly denies Guest traffic from reaching the server segment while permitting all other legitimate traffic:

```
vlan 10
 name Admin_Data
vlan 20
 name Voice
vlan 30
 name Guest_WiFi
vlan 99
 name Management_Servers
```

```
ip access-list extended RESTRICT_GUEST
 deny ip 192.168.30.0 255.255.255.0 192.168.99.0 255.255.255.0
 permit ip any any
exit

interface GigabitEthernet0/0.30
 ip access-group RESTRICT_GUEST in
exit
```

**Business Value Delivered:** guest and voice traffic are logically and access-control-isolated from the segment intended to host business-critical data and services — directly supporting data-protection and least-privilege compliance objectives.

### 2.4 Perimeter Security & Brand Protection (ASA Firewall + DMZ)

**Problem:** Publishing web/DNS services directly on the internal network exposes internal hosts to inbound Internet traffic; an uncontrolled perimeter is one of the most common vectors for breach and reputational damage.

**Engineering Solution:** A **Cisco ASA** enforces three security zones by security level — `inside1` (100), `dmz` (50), `outside` (0) — with **dynamic PAT** for outbound Internet access and a **least-privilege inbound ACL** exposing only HTTP/HTTPS and DNS to the DMZ:

```
access-list OUTSIDE_TO_DMZ extended permit tcp any host 172.16.10.10 eq www
access-list OUTSIDE_TO_DMZ extended permit tcp any host 172.16.10.10 eq 443
access-list OUTSIDE_TO_DMZ extended permit udp any host 172.16.10.11 eq domain

access-group OUTSIDE_TO_DMZ in interface outside
```

**Business Value Delivered:** public-facing services (web, DNS) are reachable from the Internet without exposing the internal network, protecting both operational continuity and the organization's public brand/reputation.

### 2.5 Secure Multi-Branch Connectivity (Site-to-Site IPSec VPN)

**Problem:** A remote branch office needs to exchange data with headquarters (e.g., database replication, shared services) without transiting the public Internet in clear text.

**Engineering Solution:** An **IKEv1 site-to-site IPSec VPN** was configured on the ASA between the local network (192.168.0.0/16) and a remote branch (10.10.10.0/24), using AES encryption, SHA hashing, and a pre-shared key, with NAT exemption so internal addressing is preserved end-to-end:

```
crypto ikev1 policy 10
 authentication pre-share
 encryption aes
 hash sha
 group 2
 lifetime 86400
exit

crypto ipsec ikev1 transform-set ESP-AES-SHA esp-aes esp-sha-hmac
crypto map MY_VPN 10 set peer 200.1.1.10
crypto map MY_VPN interface outside
```

**Business Value Delivered:** establishes the encrypted channel required for multi-site data synchronization — a prerequisite for any future distributed ERP/database replication strategy — without relying on unsecured public transport.

### 2.6 Centralized Identity, Provisioning & Observability

**Problem:** Decentralized credentials and untracked device logs make audit, compliance, and incident response difficult or impossible.

**Engineering Solution:** A dedicated Management VLAN (99) hosts:
- **DHCP/DNS/TFTP** — centralized address assignment, name resolution, and phone provisioning.
- **RADIUS/AAA** — centralized authentication, with 802.1X enabled on switches as a port-based access-control capability.
- **Syslog** — a single collection point for device event logs.

```
aaa new-model
radius-server host 192.168.99.11 key cisco123
aaa authentication dot1x default group radius
dot1x system-auth-control
```

**Business Value Delivered:** centralization of identity and logging is the foundation for auditability and access governance — both direct requirements of frameworks such as ISO 27001 and PCI-DSS.

---

## 3. Engineering Post-Mortem & Incident Management Log

Three production-style incidents surfaced during implementation and hardening. Each is documented below using a structured Root Cause Analysis (RCA) format, reflecting the incident-management discipline required to keep business services online.

### Incident 1 — Widespread DHCP Failure (Clients Receiving APIPA Addresses)

| Field | Detail |
|---|---|
| **Severity** | High — affected address assignment across multiple VLANs, a precursor to a full network-access outage |
| **Symptom** | End devices failed to obtain DHCP leases and fell back to self-assigned (APIPA) addresses |
| **Detected via** | Switch log: `%DHCP_SNOOPING-5-DHCP_SNOOPING_NONZERO_GIADDR: ... drop message with non-zero giaddr or option82 value on untrusted port ...` |
| **Root Cause** | DHCP Snooping — deployed intentionally as a rogue-DHCP-server defense — was dropping legitimately relayed DHCP packets (non-zero `giaddr`, injected by the routers' `ip helper-address`) because the relevant ports were not marked trusted, and Option 82 handling was interfering with relayed traffic. |
| **Remediation** | Declared the router-facing uplinks, the legitimate DHCP server port, and the EtherChannel's physical member ports as **trusted**; disabled Option 82 insertion (`no ip dhcp snooping information option`) on both switches. |
| **Business Impact Prevented** | A misconfigured security control (DHCP Snooping) would otherwise have silently blocked address assignment network-wide — the kind of self-inflicted outage that erodes trust in IT operations. |

```
ip dhcp snooping
ip dhcp snooping vlan 10,20,30,99
no ip dhcp snooping information option

interface range GigabitEthernet 0/1 - 2
 ip dhcp snooping trust
exit
```

> **Engineering note:** Cisco Packet Tracer does not accept `ip dhcp snooping trust` / `ip arp inspection trust` on a Port-Channel logical interface. The functional workaround applied was to trust the **physical member interfaces** of the EtherChannel instead — a simulator-specific limitation, documented here for transparency.

### Incident 2 — Port Security Violation on the Voice/Data Access Port

| Field | Detail |
|---|---|
| **Severity** | Medium — isolated to a single user/phone, but symptomatic of an under-provisioned security policy |
| **Symptom** | Port shut down / restricted traffic on the port serving the IP Phone and its daisy-chained PC |
| **Detected via** | `%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address 0009.7C32.5401 on port FastEthernet0/2.` |
| **Root Cause** | The original Port Security policy allowed only 2 sticky MAC addresses on a port that, in practice, needed to accommodate more source MACs from the phone/PC combination. |
| **Remediation** | Increased the secure MAC limit to 3, cleared previously learned sticky addresses, and reset the port (`shutdown` / `no shutdown`) to clear the violation state; complemented with DHCP Snooping trust adjustments on the EtherChannel members and `ip dhcp snooping information option allow-untrusted` to prevent related relay traffic from being dropped. |
| **Business Impact Prevented** | Restored voice and data connectivity for the affected user without weakening the underlying access-control policy — balancing security posture against user productivity. |

### Incident 3 — Guest Wireless Segment Not Receiving DHCP Correctly

| Field | Detail |
|---|---|
| **Severity** | Medium — affected only the Guest_WiFi segment, but represented a persistent user-facing service failure |
| **Symptom** | Wireless clients on the Guest VLAN could not reliably obtain DHCP addresses |
| **Root Cause** | A known DHCP broadcast-handling limitation in the generic Packet Tracer `AccessPoint-PT` device (documented in the NetCad simulation community), not a misconfiguration of the switching/routing infrastructure. |
| **Remediation** | Replaced the AccessPoint-PT with a **Linksys WRT300N** configured in access-point mode. |
| **Business Impact Prevented** | Restored guest network availability; **confirmed working** post-replacement per the source engineering notes — the one incident in this log with an explicitly recorded successful outcome. |

**Incident Management Takeaway:** each issue was triaged using device-generated log evidence rather than guesswork, root-caused to a specific mechanism (security-control interaction, policy under-provisioning, or platform limitation), and resolved with the minimum change necessary to restore service — the same discipline expected in production NOC/SRE environments supporting ERP and business-critical systems.

---

## 4. Enterprise Systems & ERP Infrastructure Readiness

The network described above is not an isolated connectivity exercise — it is engineered as the **foundation layer an ERP or centralized business-systems deployment would sit on top of.** Specifically:

- **Dedicated, isolated server segment (VLAN 99):** a natural home for a centralized **PostgreSQL / SQL Server** database tier or an **Odoo-class ERP** application/database pair, already separated from user and guest traffic by VLAN boundaries and an explicit ACL denying Guest access.
- **Gateway redundancy (HSRP):** ERP/database services hosted in VLAN 99 depend on continuous Layer 3 reachability; the active/standby router design removes the default gateway as a single point of failure for those services.
- **Centralized AAA/RADIUS with 802.1X readiness:** provides the identity layer an ERP deployment would build on for network-level access control, ahead of application-level authentication and role-based access.
- **NAT and firewall-controlled Internet egress:** ERP systems requiring outbound integrations (payment gateways, email, third-party APIs) can egress through the ASA's controlled PAT path, rather than through an unmanaged route.
- **Site-to-site IPSec VPN:** establishes the secure transport a multi-branch ERP deployment would require for database replication, shared reporting, or centralized inventory/financial consolidation across locations.
- **Centralized Syslog:** a foundation for the audit trails and operational monitoring that ERP-hosting infrastructure is expected to provide under most compliance frameworks.

**Positioning for a Backend/Systems Engineer:** this project demonstrates the ability to design and defend the *infrastructure tier* that a backend or ERP engineer's application layer depends on — segmentation, availability, and controlled connectivity are prerequisites for reliable database and business-logic operations, not afterthoughts.

---

## 5. Business Impact Summary

The matrix below maps each engineering capability to the business outcome it is architected to deliver. Because this project was built and exercised in a **simulated Packet Tracer environment**, figures below describe **design objectives and the industry-standard behavior of the mechanisms used** (e.g., HSRP's sub-second failover characteristics), not measured production uptime statistics.

| Capability | Engineering Mechanism | Business Outcome Enabled | Status |
|---|---|---|---|
| Gateway high availability | HSRPv2 active/standby, dual routers, `preempt` | Designed for continuous default-gateway availability supporting ERP/server-segment continuity | Configured; failover behavior not verification-tested in the source material |
| Link-level resiliency | LACP EtherChannel (Po1) between Core and Access | Reduced risk of access-distribution link outages affecting productivity | Configured and operational |
| Loop-free, deterministic L2 topology | PVST+ Root Primary/Secondary | Predictable failover path, reduced risk of broadcast storms | Configured |
| Data segmentation & isolation | VLANs 10/20/30/99 + inter-VLAN ACL | Guest and voice traffic isolated from the server/ERP segment | Configured and operational |
| Perimeter/brand protection | ASA firewall, 3-zone security model, DMZ ACLs | Public services exposed without exposing internal infrastructure | Configured and operational |
| Multi-site secure connectivity | Site-to-site IPSec VPN (IKEv1, AES/SHA) | Encrypted channel for cross-branch data synchronization | Configured; tunnel establishment not verification-tested in the source material |
| Centralized identity & audit readiness | RADIUS/AAA, 802.1X, Syslog | Foundation for access governance and audit trails (ISO 27001 / PCI-DSS-aligned patterns) | Configured; 802.1X end-to-end authentication not verification-tested in the source material |
| Incident resilience | Structured RCA across 3 documented incidents | Demonstrated ability to restore service quickly with minimal, targeted changes | One incident (wireless DHCP) explicitly confirmed resolved; two others resolved per configuration with no recorded output |

---

## Appendix A — Technical Reference

*(Retained for engineering audiences and reproducibility. All data below is sourced directly from the original device configurations and troubleshooting notes.)*

### A.1 Network Components

| Device | Model | Role | Relevant Information |
|---|---|---|---|
| Switch-Core | Not specified in the original documentation | Core/distribution switch | STP Root Primary; EtherChannel (Po1); hosts VLAN 99 servers; DHCP Snooping, DAI |
| Switch-Access | Not specified in the original documentation | Access switch | STP Root Secondary; EtherChannel (Po1); Port Security on Fa0/2; IP Phone, PC, Wi-Fi AP |
| Fortis-GW1 | Not specified in the original documentation | Router — HSRP Active, CME host | Subinterfaces VLAN 10/20/30/99; priority 110; link to ASA `inside1` |
| Fortis-GW2 | Not specified in the original documentation | Router — HSRP Standby | Subinterfaces VLAN 10/20/30/99; priority 100; heartbeat to GW1 |
| Fortis-ASA | Not specified in the original documentation | Perimeter firewall | Inside/Outside/DMZ; NAT (PAT); ACLs; site-to-site VPN |
| Switch-DMZ | Not specified in the original documentation | DMZ access switch | Fa0/1–24 access mode |
| Cloud-PT / ISP | Not specified in the original documentation | Simulated ISP/WAN cloud | Coaxial7 ↔ FastEthernet9 mapping |
| WEB-FORTIS | Server (Packet Tracer) | Public web server (DMZ) | HTTP/HTTPS, custom index page |
| DNS-PÚBLICO | Server (Packet Tracer) | Public DNS server (DMZ) | A records for public domain |
| DHCP/DNS/TFTP Server | Server (Packet Tracer) | Internal services (VLAN 99) | DHCP pools for VLAN 10/20/30 |
| RADIUS/AAA Server | Server (Packet Tracer) | AAA server (VLAN 99) | RADIUS client: Switch-Core |
| Syslog Server | Server (Packet Tracer) | Centralized logging (VLAN 99) | Service enabled |
| IP Phone 7960 | Cisco 7960 | VoIP endpoint | Registered via CME, extension 1001 |
| Access Point | Linksys WRT300N (replaced original AccessPoint-PT) | Wireless AP, Guest VLAN | Replaced during troubleshooting (Incident 3) |
| SERVER EXTERNAL | Server (Packet Tracer) | External/Internet-side host | Represents a host beyond the ISP cloud |
| PC-Admin | Not specified in the original documentation | End-user host (VLAN 10) | Switch-Core Fa0/1 |
| PC-Staff | Not specified in the original documentation | End-user host (VLAN 10) | Switch-Access Fa0/2 |

### A.2 IP Addressing Plan

| Device / VLAN | IP Address | Subnet Mask | Gateway | Purpose |
|---|---|---|---|---|
| VLAN 10 – Admin_Data (HSRP VIP) | 192.168.10.1 | 255.255.255.0 | — | Virtual gateway |
| Fortis-GW1 Gi0/0.10 | 192.168.10.2 | 255.255.255.0 | — | HSRP Active |
| Fortis-GW2 Gi0/0.10 | 192.168.10.3 | 255.255.255.0 | — | HSRP Standby |
| VLAN 20 – Voice (HSRP VIP) | 192.168.20.1 | 255.255.255.0 | — | Virtual gateway |
| Fortis-GW1 Gi0/0.20 | 192.168.20.2 | 255.255.255.0 | — | HSRP Active |
| Fortis-GW2 Gi0/0.20 | 192.168.20.3 | 255.255.255.0 | — | HSRP Standby |
| VLAN 30 – Guest_WiFi (HSRP VIP) | 192.168.30.1 | 255.255.255.0 | — | Virtual gateway |
| Fortis-GW1 Gi0/0.30 | 192.168.30.2 | 255.255.255.0 | — | HSRP Active |
| Fortis-GW2 Gi0/0.30 | 192.168.30.3 | 255.255.255.0 | — | HSRP Standby |
| VLAN 99 – Management_Servers (HSRP VIP) | 192.168.99.1 | 255.255.255.0 | — | Virtual gateway |
| Fortis-GW1 Gi0/0.99 | 192.168.99.2 | 255.255.255.0 | — | HSRP Active |
| Fortis-GW2 Gi0/0.99 | 192.168.99.3 | 255.255.255.0 | — | HSRP Standby |
| Fortis-GW1 Gi0/2 (heartbeat) | 10.0.0.1 | 255.255.255.252 | — | HSRP heartbeat to GW2 |
| Fortis-GW2 Gi0/2 (heartbeat) | 10.0.0.2 | 255.255.255.252 | — | HSRP heartbeat to GW1 |
| Fortis-GW1 Gi0/1 | 172.16.0.2 | 255.255.255.252 | 172.16.0.1 | Link to ASA `inside1` |
| Fortis-GW2 Gi0/1 | 172.16.0.6 | 255.255.255.252 | 172.16.0.5 | Link toward ASA (ASA-side address not specified in the provided ASA config) |
| Fortis-ASA `inside1` | 172.16.0.1 | 255.255.255.252 | — | Link to Fortis-GW1 |
| Fortis-ASA `outside` | 200.1.1.2 | 255.255.255.248 | 200.1.1.1 | Internet-facing |
| Fortis-ASA `dmz` | 172.16.10.1 | 255.255.255.0 | — | DMZ gateway |
| WEB-FORTIS | 172.16.10.10 | 255.255.255.0 | 172.16.10.1 | Public web server |
| DNS-PÚBLICO | 172.16.10.11 | 255.255.255.0 | 172.16.10.1 | Public DNS server |
| DHCP/DNS/TFTP Server | 192.168.99.10 | 255.255.255.0 | 192.168.99.1 | Internal services |
| RADIUS/AAA Server | 192.168.99.11 | 255.255.255.0 | 192.168.99.1 | AAA/RADIUS |
| Syslog Server | 192.168.99.12 | 255.255.255.0 | 192.168.99.1 | Centralized logging |
| SERVER EXTERNAL | 200.1.1.6 | 255.255.255.248 | 200.1.1.2 | External test server |
| VPN Remote Network | 10.10.10.0 | 255.255.255.0 | — | Remote branch subnet |
| VPN Peer Address | 200.1.1.10 | — | — | Remote VPN peer |

### A.3 Device Configuration Highlights

**Switch-Core**
```
hostname Switch-Core

spanning-tree mode pvst
spanning-tree vlan 10,20,30,99 root primary

interface range FastEthernet 0/3 - 5
 switchport mode access
 switchport access vlan 99
 spanning-tree portfast
 no shutdown
exit

interface FastEthernet 0/1
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
 no shutdown
exit
```

**Switch-Access**
```
hostname Switch-Access

spanning-tree mode pvst
spanning-tree vlan 10,20,30,99 root secondary

interface FastEthernet 0/2
 switchport mode access
 switchport access vlan 10
 switchport voice vlan 20
 spanning-tree portfast
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
 no shutdown
exit

interface FastEthernet 0/10
 switchport mode access
 switchport access vlan 30
 spanning-tree portfast
 no shutdown
exit
```

**Fortis-ASA — Security Zones**
```
interface GigabitEthernet1/1
 nameif inside1
 security-level 100
 ip address 172.16.0.1 255.255.255.252
 no shutdown
exit

interface GigabitEthernet1/2
 nameif outside
 security-level 0
 ip address 200.1.1.2 255.255.255.248
 no shutdown
exit

interface GigabitEthernet1/3
 nameif dmz
 security-level 50
 ip address 172.16.10.1 255.255.255.0
 no shutdown
exit
```

**Switch-DMZ**
```
hostname Switch-DMZ

interface range FastEthernet 0/1 - 24
 switchport mode access
 no shutdown
exit
```

**Cisco CME (Fortis-GW1) — IP Telephony**
```
license boot module c2900 technology-package uck9

telephony-service
 max-ephones 5
 max-dn 5
 ip source-address 192.168.20.1 port 2000
 auto assign 1 to 5
exit

ephone-dn 1
 number 1001
exit

ephone-dn 2
 number 1002
exit
```

### A.4 Validation & Testing Log

| Test | Objective | Procedure | Recorded Result |
|---|---|---|---|
| DMZ reachability | Confirm ASA-to-web-server path across DMZ | `ping dmz 172.16.10.10` | Not specified in the original documentation |
| Server-to-gateway reachability | Confirm VLAN 99 servers reach the HSRP virtual IP | `ping 192.168.99.1` | Not specified in the original documentation |
| IP Phone DHCP/CME registration | Confirm phone obtains VLAN 20 address and registers extension 1001 | Power on IP Phone 7960, observe registration | Not specified in the original documentation |
| DHCP service recovery | Confirm DHCP works after Snooping/Port Security/AP fixes | Observe client address assignment post-remediation | **Confirmed working** after AP replacement (Incident 3) |

### A.5 Repository Structure

```
fortis-network-infrastructure/
├── README.md
├── project.pkt
├── configs/
│   ├── switch-core.txt
│   ├── switch-access.txt
│   ├── fortis-gw1.txt
│   ├── fortis-gw2.txt
│   ├── fortis-asa.txt
│   ├── switch-dmz.txt
│   └── fixes/
│       ├── dhcp-snooping-fix.txt
│       ├── port-security-fix.txt
│       └── wireless-ap-fix.txt
└── docs/
    └── images/
        ├── 01-network-topology.png
        ├── 02-vlan-configuration.png
        ├── 03-routing-verification.png
        ├── 04-dhcp-verification.png
        ├── 05-security-configuration.png
        └── 06-troubleshooting-evidence.png
```

---

## Conclusion

This project demonstrates the ability to translate business continuity, data-isolation, and compliance-readiness requirements into a concrete, defensible network architecture — and to diagnose and resolve real engineering incidents along the way using structured root-cause analysis rather than trial and error. The infrastructure documented here — redundant gateways, hardened access layers, a firewalled DMZ, and centralized identity/logging services — is the same class of foundation on which production ERP, database, and business-systems platforms are built, positioning this work as a credible reference point for infrastructure, backend/ERP systems, and business-analyst roles alike.
