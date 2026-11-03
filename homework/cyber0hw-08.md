# IT HW 8 - Data Center Risk Assessment & Remediation Roadmap
Jae Eon Yoo - CYBER 444

This report is about Meridian Financial Services' primary data center. All findings come from the Meridian Site Survey Findings. When the survey did not give a number I needed, I made an assumption and I say it in the text.

## Part 1 - Executive Summary
Meridian's data center is not ready for a power outage, and its servers can be controlled with a factory default password. The backup generator is 200KW, but the building uses 306 kW, so during a power outage the generator will be overloaded and the building will lose power. The battery backup units (uninterruptible power supplies, or UPS) are also smaller than what the servers use now. Also, every server has a remote management card that still uses the default login and is on the same network as the banking applications. Anyone who gets into that network can turn off or take over any server. There is also only one internet provider, one firewall, and no staff on site at night or on weekends.

ITIC's 2024 survey found that one hour of downtime costs more than $300,000 for over 90% of mid-size and large companies. With this number, a 6-hour power outage after hours (4 hours waiting for the vendor and 2 hours to recover) would cost about $1.8 million. A firewall failure that takes 8-24 hours to replace would cost about $2.4-7.2 million. A ransomware attack using the default passwords could cost about $10.22 million, which is the average U.S. data breach cost in IBM's 2025 report. This does not include penalties from regulators, who already flagged availability and physical security. My top recommendation is to change the default management passwords and move the cards to a separate network this week, because it costs almost nothing. After that, Meridian should approve money to replace the generator and UPS.

## Part 2 - Risk Register
Score = Likelihood x Impact. A score of 15 or higher is Critical.
| Risk ID | Category | Description | Likelihood (1-5) | Impact (1-5) | Score | Current Controls | Recommended Control | Cost Category |
| R-01 | Power | One 200 kW generator for a 306 kW facility load. No second generator. | 4 | 5 | 20 (Critical) [1] | 72-hour fuel, ATS (12 s) | Two generators (N+1), each 400 kW or more | High |
| R-02 | Power | Two 80 kVA UPS units (128-160 kW total) for a 180 kW IT load. No spare capacity. | 4 | 5 | 20 (Critical) [2] | A/B feeds to PDUs | Check real UPS load now, then expand UPS to N+1 | High |
| R-03 | Power | Servers are single-corded, so one PDU or UPS failure takes down all servers on that side. | 3 | 4 | 12 | Two PDUs per row | Rack transfer switches now, dual power supplies at refresh | Medium |
| R-04 | Cooling | Rows 5-8 have no containment, and hot air exhausts to the raised floor, so hot and cold air mix. | 3 | 3 | 9 | Containment in rows 1-4 only | Add containment to rows 5-8 | Medium |
| R-05 | Cooling | No spare CRAC compressor on site. Parts take 48-72 hours. | 2 | 3 | 6 | 5 running + 1 spare CRAC | Keep one compressor kit on site | Low |
| R-06 | Physical Security | No cameras inside the server room. | 3 | 4 | 12 | Badge + PIN at the door | Cameras on every aisle, 90-day retention | Low |
| R-07 | Physical Security | Any badge holder can escort visitors, not trained staff. | 3 | 4 | 12 | Mantrap, badge + PIN | Only trained facilities/security staff escort; log the escort name | Low |
| R-08 | Physical Security | Racks have no doors or locks. | 3 | 4 | 12 | Room access only | Lockable doors on core banking and trading racks | Medium |
| R-09 | Network | One 1 Gbps ISP, no BGP. One fiber cut takes the bank offline. | 3 | 5 | 15 (Critical) [3] | None | Second ISP on a different path with BGP | Medium |
| R-10 | Network | One PA-3250 firewall, no HA. | 3 | 5 | 15 (Critical) [4] | None | Second PA-3250 in an HA pair | Medium |
| R-11 | Network | iDRAC cards on the production VLAN with default root / calvin still active. | 5 | 5 | 25 (Critical) [5] | None | Disable default account, unique passwords, separate management VLAN | Low |
| R-12 | Network | IPMI over LAN on, SNMP v1 "public", weak Monitor123 password, 4-year-old firmware, self-signed cert. | 4 | 4 | 16 (Critical) [6] | HTTPS only | Turn off IPMI over LAN and SNMP v1, change password, update firmware | Low |
| R-13 | Operational | Staff on site only 7 AM-7 PM weekdays (about 36% of the week). Vendor needs up to 4 hours to arrive. | 4 | 4 | 16 (Critical) [7] | Alarm pages the vendor | 24/7 remote monitoring and internal on-call | Medium |

**How its scored.** Likelihood is high when the problem can happen today with nothing else going wrong (R-11 is 5 because the default password works right now). Impact is 5 when the whole bank stops (power loss, network loss, server takeover), 4 when part of operations or customer data is affected, and 3 when it only reduces safety margin.

**Critical worst cases**
[1] R-01: Power goes out on a Friday night. The generator starts but sees 306 kW on a 200 kW rating and trips. The UPS batteries run out and everything goes down. Nobody is on site, and even when the vendor arrives the generator still cannot run the building.
[2] R-02: The UPS is already over its rating, so it may be in bypass with no battery protection. Then even a short power flicker drops every server. If one UPS fails, half of the servers go down because they have only one power supply.
[3] R-09: A construction crew cuts the ISP-A fiber during trading hours. Trading, online banking, and VPN all stop until the fiber is fixed.
[4] R-10: The firewall fails after a bad update. All internet and partner traffic stops. I assumed a next-business-day replacement because the survey does not say, so it could be 8-24 hours offline.
[5] R-11: Malware from a phishing email reaches the 10.0.0.x network, logs in to every iDRAC with root / calvin, and wipes the core banking servers. The server security software cannot see it because iDRAC works below the operating system.
[6] R-12: Even with a new root password, IPMI over LAN lets an attacker get password hashes without logging in (CVE-2013-4786) and crack weak passwords like Monitor123.
[7] R-13: A CRAC fails at 1 AM on Saturday in row 7. Nobody is on site and the vendor takes up to 4 hours, so the servers in rows 5-8 overheat and shut down.

## Part 3 - Uptime Tier Analysis
**Current tier: Tier I, and it does not fully meet Tier I.**
| Criterion | Requirement | Meridian | Met? |
| Tier I | UPS, cooling, and generator sized for the load | Cooling is fine (150 tons running vs. about 51 tons needed). UPS and generator are smaller than the load. | Partly |
| Tier II | N+1 for generators, UPS, and cooling | Cooling is N+1. UPS has no spare. Only one generator. | No |
| Tier III | Redundant paths, maintenance without downtime | Servers are single-corded, so only one path | No |

**Three biggest gaps to Tier II**
| # | Gap | Fix | Estimated cost |
| 1 | Generator is smaller than the load (200 vs. 306 kW) | Replace with 400 kW or larger | $150K-$300K (DEPCO lists 200-500 kW units at $75K-$200K before installation) |
| 2 | Only one generator | Add a second unit with paralleling gear | $200K-$400K (my estimate) |
| 3 | UPS smaller than the IT load, no spare | Expand UPS to N+1 | $100K-$250K (my estimate) |

| Tier | Availability | Downtime per year |
| I | 99.671% | 28.8 hours |
| II | 99.741% | 22.7 hours |
| III | 99.982% | 1.6 hours |
| IV | 99.995% | 26.3 minutes |

**Recommendation: go to Tier II.** Tier II allows about 6.1 fewer hours of downtime per year. At $300,000 per hour, that is about $1.84 million per year, and the total cost is about $450K-$950K, so it pays back in the first year. I do not recommend Tier III now because it needs dual-corded servers and a second power path, which means replacing many servers.

## Part 4 - Remediation Roadmap
### Immediate (0-30 days)
| Action | Risk IDs | Owner | Cost | Score after | Success criterion |
| Disable root/calvin, set unique passwords, move iDRACs to a management VLAN | R-11 | Systems Admin | Under $2K | 25 -> 5 | Login with root/calvin fails on 100% of iDRACs, and they cannot be reached from the production VLAN |
| Turn off IPMI over LAN and SNMP v1, change svc-monitor password, update firmware | R-12 | Systems Admin | Under $5K | 16 -> 4 | 0 iDRACs with IPMI over LAN or SNMP v1 enabled |
| Check real UPS load with the vendor, write a load-shed plan | R-01, R-02 | Facilities Manager | $5K-$10K | 20 -> 15 each | Vendor report of UPS load and a load-shed list approved by the CTO |
| Only trained staff can escort visitors | R-07 | Facilities Manager | $0 | 12 -> 6 | 100% of visitor log entries for 30 days name an approved escort |

### Short-term (1-6 months)
| Action | Risk IDs | Owner | Cost | Score after | Success criterion |
| Second ISP with BGP | R-09 | Network Engineer | $10K-$40K/yr | 15 -> 5 | Traffic fails over in under 60 seconds in a test |
| Second firewall in HA | R-10 | Network Engineer | $40K-$70K | 15 -> 5 | Forced failover does not drop trading sessions |
| 24/7 remote monitoring and internal on-call | R-13 | IT Operations Manager | $50K-$100K/yr | 16 -> 8 | After-hours alarms answered within 15 minutes for 3 months |
| Cameras and rack locks | R-06, R-08 | Information Security Officer | $15K-$55K | 12 -> 6 each | Every rack face recorded, and all critical racks locked |
| Containment in rows 5-8 and a spare compressor kit | R-04, R-05 | Facilities Manager | $45K-$110K | 9 -> 3, 6 -> 3 | Rows 5-8 inlet temperature within 2 F of rows 1-4 |
| Rack transfer switches for critical servers | R-03 | Systems Admin | $10K-$30K | 12 -> 6 | Critical servers stay up when one PDU is turned off |

### Long-term (6-18 months)
| Action | Risk IDs | Owner | Cost | Score after | Success criterion |
| Replace generator with N+1 units, 400 kW or more | R-01 | CTO / Facilities Director | $350K-$700K | 20 -> 5 | Full-load test runs 306 kW for 4 hours with one generator off |
| Expand UPS to N+1 | R-02 | CTO / Facilities Director | $100K-$250K | 20 -> 5 | UPS load stays under 80% with one module removed |

## Part 5 - MTTR & Reliability Calculations
Availability = MTBF / (MTBF + MTTR). For MTTR I used the survey: no staff after hours, 4-hour vendor arrival, next-business-day UPS parts, and 48-72 hours for CRAC compressor parts.

| Component | MTBF (source) | MTTR | Availability |
| Generator (R-01) | 1,662 run hours (NREL/TP-5C00-76553, well-maintained standby diesel) | 32 h = 4 h vendor + 24 h parts (assumed next business day) + 4 h repair | 1,662 / 1,694 = 98.11% |
| UPS (R-02) | 500,000 h (Legrand UPS example) | 44 h = about 40 h average parts wait (24 h on weekdays, 60 h on weekends) + 4 h install | 500,000 / 500,044 = 99.991% |
| CRAC compressor (R-05) | 175,200 h = 20 years (ASHRAE median service life) | 70 h = 4 h vendor + 60 h parts + 6 h install | 175,200 / 175,270 = 99.960% |

**Compared to Uptime targets (Tier I 99.671%, Tier II 99.741%):** the generator is below both, so it is the weakest part, and this is why a second generator is needed. The UPS and CRAC numbers are above both targets, but the UPS number assumes it runs within its rating, which is not true now. Also, cooling has a lot of extra capacity (about 2 of the 5 running CRACs are enough), so the real cooling risk is the long repair time with nobody on site, not the compressor itself.

## Sources Used
- ITIC 2024 Hourly Cost of Downtime Survey, Part 2: https://calyptix.com/wp-content/uploads/ITIC-2024-Hourly-Cost-of-Downtime-Survey-Results-Part-2.pdf
- CyberScoop, IBM Cost of a Data Breach 2025: https://cyberscoop.com/ibm-cost-data-breach-2025/
- NREL/TP-5C00-76553, Emergency Diesel Generator Reliability (2020): https://docs.nlr.gov/docs/fy20osti/76553.pdf
- Legrand, MTTR and MTBF for UPS: https://www.legrand.com/datacenter/gb-en/news/mttr-and-mtbf-key-metrics-for-maximizing-ups-reliability-and-uptime
- ASHRAE equipment life expectancy chart (via Shipley Energy): https://www.shipleyenergy.com/wp-content/uploads/2025/09/ASHRAE_Chart_HVAC_Life_Expectancy.pdf
- DatacenterDynamics, data center tier classifications: https://datacenterdynamics.com/en/analysis/understanding-data-center-tier-classifications
- DEPCO, diesel generator costs: https://www.depco.com/faq/diesel-generator-costs/
- Dell, IPMI v2.0 Password Hash Disclosure (CVE-2013-4786): https://www.dell.com/support/kbdoc/en-us/000222162
- Uptime Institute tier availability targets from the assignment tip