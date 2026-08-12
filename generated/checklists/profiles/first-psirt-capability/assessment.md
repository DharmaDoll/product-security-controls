# FIRST PSIRT capability assessment profile

Generated from a reviewed, integrity-recorded FIRST PSIRT Maturity Document snapshot and PSIRT Services Framework 1.1 snapshot. Do not edit manually.

This is an organization assessment template, not a control package or compliance claim. Repository check references are supporting evidence only. Every public result and evidence-freshness field starts as `NOT_CHECKED`.

The levels are cumulative: assessing Level 2 includes Level 1 rows, and assessing Level 3 includes Levels 1 and 2. A level is never inferred from a partial set of rows.

## Row inventory

| Minimum level | Rows | Cumulative rows |
|---:|---:|---:|
| 1 (Basic) | 6 | 6 |
| 2 (Intermediate) | 6 | 12 |
| 3 (Advanced) | 6 | 18 |

## Capability rows

| Row | Minimum level | Capability area | Capability | Responsible role | FIRST services | Repository supporting checks | Result |
|---|---:|---|---|---|---|---|---|
| PSIRT-B-001 | 1 | Operational Foundations | Executive sponsorship, scope, budget, roles, and initial response policies are documented and current. | executive-sponsor | OF-STRATEGIC Strategic foundation; OF-TACTICAL Tactical foundation | PSB-GOV-003-VPR-006 | NOT_CHECKED |
| PSIRT-B-002 | 1 | Stakeholder Ecosystem Management | Internal teams, customers, finders, coordinators, suppliers, and downstream users have named communication routes. | psirt-lead | 1.1 Internal Stakeholder Management; 1.4 Downstream Stakeholder Management; 1.5 Incident Communications Coordination | PSB-GOV-003-VPR-006 | NOT_CHECKED |
| PSIRT-B-003 | 1 | Vulnerability Discovery | Public and internal vulnerability intake accepts protected reports, acknowledges receipt, and preserves reporter confidentiality. | psirt-intake | 2.1 Intake of Vulnerability Reporting | PSB-GOV-003-VPR-001; PSB-GOV-003-VPR-008 | NOT_CHECKED |
| PSIRT-B-004 | 1 | Vulnerability Triage and Analysis | Every accepted report is qualified, analyzed, scored consistently, and linked to exact affected products and supported versions. | vulnerability-analyst | 3.1 Vulnerability Qualification; 3.3 Vulnerability Reproduction | PSB-GOV-003-VPR-001; PSB-GOV-003-VPR-002; PSB-GOV-003-VPR-003; PSB-GOV-003-VPR-005 | NOT_CHECKED |
| PSIRT-B-005 | 1 | Remediation | A named product owner evaluates remediation, mitigation, transfer, or governed acceptance and tracks the decision to closure. | product-owner | 4.1 Remedy Release Management Plan; 4.2 Remediation | PSB-GOV-003-VPR-005; PSB-GOV-003-VPR-006; PSB-GOV-003-VPR-007 | NOT_CHECKED |
| PSIRT-B-006 | 1 | Vulnerability Disclosure | Affected stakeholders receive an accurate advisory or equivalent notice with supported-product scope and remedy guidance. | psirt-communications | 5.1 Notification; 5.3 Disclosure | PSB-GOV-003-VPR-006 | NOT_CHECKED |
| PSIRT-I-001 | 2 | Operational Foundations | The charter, organizational model, staffing, tooling, procedures, support lifecycle, product registry, and baseline metrics are reviewed together. | psirt-lead | OF-STRATEGIC Strategic foundation; OF-TACTICAL Tactical foundation; OF-OPERATIONAL Operational foundation | PSB-GOV-001-INC-001; PSB-GOV-001-INC-007 | NOT_CHECKED |
| PSIRT-I-002 | 2 | Stakeholder Ecosystem Management | Internal and downstream stakeholders participate in rehearsed incident communication and coordinated vulnerability decisions. | incident-coordinator | 1.1 Internal Stakeholder Management; 1.4 Downstream Stakeholder Management; 1.5 Incident Communications Coordination | PSB-GOV-001-INC-003; PSB-GOV-003-VPR-006 | NOT_CHECKED |
| PSIRT-I-003 | 2 | Vulnerability Discovery | The PSIRT looks for unreported and internally found vulnerabilities and links component intelligence to its product inventory. | vulnerability-intelligence | 2.2 Identify Unreported Vulnerabilities; 2.3 Monitoring for Product Component Vulnerabilities; 2.4 Identifying New Vulnerabilities | PSB-GOV-001-INC-001; PSB-GOV-001-INC-006; PSB-GOV-003-VPR-004 | NOT_CHECKED |
| PSIRT-I-004 | 2 | Vulnerability Triage and Analysis | A maintained reproduction environment and expert escalation path support repeatable analysis of relevant product versions. | vulnerability-analyst | 3.2 Established Finders; 3.3 Vulnerability Reproduction | PSB-GOV-003-VPR-002; PSB-GOV-003-VPR-003 | NOT_CHECKED |
| PSIRT-I-005 | 2 | Remediation and Disclosure | Formal remedy release, notification, and coordination plans bind exact affected releases to a predictable response workflow. | release-manager | 4.1 Remedy Release Management Plan; 4.2 Remediation; 5.1 Notification; 5.2 Coordination; 5.3 Disclosure | PSB-GOV-003-VPR-002; PSB-GOV-003-VPR-006 | NOT_CHECKED |
| PSIRT-I-006 | 2 | Metrics, Training, and Feedback | The PSIRT measures intake, triage, remediation, disclosure, and channel health and trains its team using reviewed feedback. | psirt-program-manager | 1.7 Stakeholder Metrics; 2.5 Vulnerability Discovery Metrics; 4.4 Vulnerability Release Metrics; 5.4 Vulnerability Metrics; 6.1 Training the PSIRT; 6.5 Feedback Mechanisms |  | NOT_CHECKED |
| PSIRT-A-001 | 3 | Operational Foundations | Long-running policies, funding, staffing, tooling, and cost evidence support both normal vulnerability workload and severe incidents. | executive-sponsor | OF-STRATEGIC Strategic foundation; OF-TACTICAL Tactical foundation; OF-OPERATIONAL Operational foundation |  | NOT_CHECKED |
| PSIRT-A-002 | 3 | Stakeholder Ecosystem Management | The PSIRT maintains direct finder, peer, supplier, customer, and community engagement and uses stakeholder metrics for improvement. | psirt-communications | 1.2 Finder Community Engagement; 1.3 Community and Organizational Engagement; 1.6 Finder Recognition and Acknowledgement; 1.7 Stakeholder Metrics |  | NOT_CHECKED |
| PSIRT-A-003 | 3 | Vulnerability Discovery | Proactive product, component, exploit, conference, publication, and researcher monitoring produces measured and reviewable discovery outcomes. | vulnerability-intelligence | 2.2 Identify Unreported Vulnerabilities; 2.3 Monitoring for Product Component Vulnerabilities; 2.4 Identifying New Vulnerabilities; 2.5 Vulnerability Discovery Metrics | PSB-GOV-001-INC-006; PSB-GOV-001-INC-007; PSB-GOV-003-VPR-004 | NOT_CHECKED |
| PSIRT-A-004 | 3 | Remediation and Incident Handling | Advanced incident handling coordinates severe or multi-product vulnerabilities, preserves evidence, and validates recovery across affected releases. | incident-commander | 4.2 Remediation; 4.3 Incident Handling | PSB-GOV-001-INC-002; PSB-GOV-001-INC-003; PSB-GOV-001-INC-005 | NOT_CHECKED |
| PSIRT-A-005 | 3 | Disclosure and Service Metrics | Multi-party disclosure playbooks and release metrics demonstrate predictable, accurate, and improving stakeholder outcomes. | psirt-program-manager | 4.4 Vulnerability Release Metrics; 5.2 Coordination; 5.3 Disclosure; 5.4 Vulnerability Metrics | PSB-GOV-003-VPR-006; PSB-GOV-003-VPR-008 | NOT_CHECKED |
| PSIRT-A-006 | 3 | Training and Continuous Improvement | Development, validation, legal, support, communications, executive, and other stakeholder groups receive role-specific recurring PSIRT education. | security-education | 1.1 Internal Stakeholder Management; 6.2 Training the Development Team; 6.3 Training the Validation Team; 6.4 Continuing Education for Stakeholders; 6.5 Feedback Mechanisms |  | NOT_CHECKED |
