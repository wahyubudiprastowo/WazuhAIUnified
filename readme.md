# Wazuh MCP Unified SOC Platform

## Enterprise AI-Enhanced Security Operations Center Platform

![SOC Platform](https://img.shields.io/badge/SOC-Platform-blue)
![AI](https://img.shields.io/badge/AI-Security%20Assistant-purple)
![Wazuh](https://img.shields.io/badge/Wazuh-Integrated-green)
![MCP](https://img.shields.io/badge/MCP-Enabled-orange)

---

# Table of Contents

1. Overview
2. Platform Vision
3. Key Features
4. Architecture Overview
5. Component Architecture
6. Data Flow Architecture
7. SOC Capability Model
8. System Requirements
9. Installation Guide
10. Environment Configuration
11. Wazuh Integration
12. Elasticsearch/OpenSearch Integration
13. AI Provider Configuration
14. Docker Deployment
15. Dashboard Module Explanation
16. SOC Analyst Operation Guide
17. AI Security Assistant Workflow
18. Threat Intelligence Workflow
19. Performance Optimization
20. Security Hardening
21. Monitoring and Maintenance
22. Troubleshooting
23. Backup and Recovery
24. Upgrade Procedure
25. Developer Guide
26. API Overview
27. Production Deployment Recommendation
28. Future Development Roadmap
29. Conclusion

---

# 1. Overview

## What is Wazuh MCP Unified?

Wazuh MCP Unified adalah platform Security Operations Center (SOC) modern yang menggabungkan:

- Wazuh Security Monitoring
- Security Event Analytics
- MCP (Model Context Protocol)
- AI Security Assistant
- Threat Intelligence
- SOC Automation
- Security Investigation Workflow
- Real-Time Dashboard

Platform ini dirancang bukan hanya sebagai dashboard monitoring, tetapi sebagai:

> AI-assisted Security Operations Platform

yang membantu analyst melakukan:

- Detection
- Investigation
- Threat Analysis
- Incident Response
- Security Automation

---

# 2. Platform Vision

SOC tradisional biasanya memiliki banyak tool terpisah:

```
SIEM
 |
Threat Intelligence
 |
Case Management
 |
Automation
 |
AI Assistant
 |
Reporting
```

Akibatnya analyst harus berpindah-pindah sistem.

Wazuh MCP Unified menggabungkan workflow tersebut:

```
Security Event

      |

Detection

      |

Context Enrichment

      |

AI Analysis

      |

Investigation

      |

Response Recommendation

      |

Incident Resolution
```

---

# 3. Key Features

## 3.1 Security Monitoring

Kemampuan:

- Security event monitoring
- Alert monitoring
- Severity classification
- Agent monitoring
- Rule analysis
- Security trend analysis

Contoh:

```
Critical Alert

Source:
SERVER-01

Rule:
Suspicious PowerShell

Severity:
Critical

Time:
2026-09-24 01:00
```

---

# 3.2 AI Security Assistant

AI digunakan sebagai virtual SOC analyst.

Kemampuan:

- Explain security alert
- Analyze finding
- Summarize investigation
- Recommend action
- Generate security report

Contoh:

Input:

```
Analyze this alert
```

AI menghasilkan:

```
Threat Summary

Evidence

Risk Level

Possible Attack Technique

Recommended Investigation

Recommended Response
```

---

# 3.3 MCP Security Integration

MCP memungkinkan AI berinteraksi dengan security tools secara terstruktur.

Flow:

```
AI Assistant

      |

MCP Layer

      |

Security Tools

      |

Security Data
```

Kemampuan:

- Query security data
- Retrieve context
- Analyze findings
- Execute security workflow

---

# 3.4 Threat Intelligence

Kemampuan:

- IOC analysis
- IP reputation
- Domain reputation
- Malware context
- Threat enrichment

Contoh:

```
IOC:

185.x.x.x

Detected:

SERVER-01

Related Alert:

5

Risk:

High
```

---

# 3.5 Security Automation

Automation membantu mengurangi pekerjaan manual analyst.

Contoh:

```
Alert Created

      |

Collect Evidence

      |

AI Analysis

      |

Generate Recommendation

      |

Analyst Approval

      |

Response
```

---

# 4. Architecture Overview

```
                         SOC Analyst

                              |

                              |

                     Web SOC Dashboard

                              |

                              |

                       Backend API

                              |

              +---------------+---------------+

              |                               |

              |                               |

        MCP Security Layer              AI Provider

              |

              |

       Security Data Layer

              |

              |

    Wazuh Manager / Indexer

              |

              |

       Endpoint Security Events

```

---

# 5. Component Architecture

---

# 5.1 Frontend Dashboard

Location:

```
static/
```

Responsibilities:

- SOC visualization
- Analyst workflow
- Security monitoring
- AI interaction
- Platform status

Component:

```
index.html

app.js

styles.css
```

---

# 5.2 Backend API Server

Main service:

```
server.py
```

Responsibilities:

- REST API
- Dashboard backend
- Security query
- Data aggregation
- AI integration

---

# 5.3 SOC Automation Engine

Component:

```
soc_automation.py
```

Responsibilities:

- AI security analysis
- Finding assessment
- Context preparation
- Investigation assistance

---

# 5.4 Security Data Layer

Data source:

- Wazuh
- Elasticsearch/OpenSearch
- Security Index

Example:

```
wazuh-alerts-*

security-events-*

security-findings-*
```

---

# 6. Data Flow Architecture

## Security Event Pipeline

```
Endpoint

 |

Wazuh Agent

 |

Wazuh Manager

 |

Indexer

 |

Backend API

 |

SOC Dashboard

 |

Analyst
```

---

# AI Investigation Pipeline

```
Alert

 |

Context Builder

 |

Collect:

- Host Data
- User Data
- Event History
- IOC
- Threat Intel

 |

AI Model

 |

Analysis Result

 |

SOC Analyst
```

---

# 7. SOC Capability Model

Platform mendukung workflow:

## L1 Analyst

Focus:

- Monitoring
- Alert triage
- Initial analysis

Workflow:

```
Alert Received

↓

Review Severity

↓

Review AI Summary

↓

Escalate
```

---

## L2 Analyst

Focus:

- Investigation
- Correlation
- Root cause analysis

Workflow:

```
Alert

↓

Timeline Analysis

↓

Evidence Collection

↓

Determine Incident
```

---

## L3 Threat Hunter

Focus:

- Advanced hunting
- Detection improvement

Workflow:

```
Hypothesis

↓

Search Event

↓

Find Pattern

↓

Create Detection
```

---

# 8. System Requirements

## Minimum Production

```
CPU:
8 Core

RAM:
16 GB

Storage:
200 GB SSD

OS:
Ubuntu 22.04+
```

---

## Recommended Enterprise SOC

```
CPU:
16-32 Core

RAM:
32-64 GB

Storage:
500GB+

Network:
1Gbps+
```

---

# 9. Installation Guide

## Step 1

Clone Repository

```bash
git clone <repository-url>

cd wazuh-mcp-unified
```

---

## Step 2

Install Python Environment

```bash
python3 -m venv venv
```

Activate:

```bash
source venv/bin/activate
```

Install dependency:

```bash
pip install -r requirements.txt
```

---

# 10. Environment Configuration

Create:

```
.env
```

Example:

```env
WAZUH_URL=https://wazuh-server:55000

INDEXER_URL=https://indexer-server:9200

AI_PROVIDER_BASE_URL=http://ai-provider/api/v1

AI_MODEL=auto

AI_MAX_TOKENS=4096
```

---

# 11. Wazuh Integration

Requirement:

- Wazuh Manager aktif
- API aktif
- Indexer tersedia

Test:

```bash
curl https://wazuh-server:55000
```

Expected:

```
Wazuh API Response
```

---

# 12. Elasticsearch/OpenSearch Integration

Platform membutuhkan akses:

```
Indexer

 |

Security Index

 |

Aggregation Query
```

Untuk environment besar:

Gunakan:

- aggregation
- caching
- summary index
- pagination

---

# 13. AI Provider Configuration

AI provider menggunakan:

```
AI_PROVIDER_BASE_URL
```

Example:

```
http://10.x.x.x:20128/api/v1
```

Recommended:

```
AI_MAX_TOKENS=4096
```

Streaming mode:

```
stream=true
```

---

# 14. Docker Deployment

Build:

```bash
docker compose build
```

Jika ada perubahan source:

```bash
docker compose up --build
```

Start:

```bash
docker compose up -d
```

Check:

```bash
docker ps
```

---

# 15. Dashboard Module Explanation

# Security Overview

Tujuan:

Memberikan situational awareness.

Menampilkan:

- Active alert
- Severity
- Trend
- Platform status

---

# Alerts Module

Fungsi:

Alert investigation.

Data:

- Rule
- Severity
- Source
- Timestamp
- Evidence

---

# Findings Module

Fungsi:

Security findings management.

Berisi:

- Risk
- Evidence
- AI assessment
- Recommendation

---

# Threat Intelligence Module

Fungsi:

IOC investigation.

Menampilkan:

- IOC
- Reputation
- Related events
- Detection history

---

# AI Assistant Module

Fungsi:

Virtual SOC Analyst.

Kemampuan:

- Explain alert
- Investigate
- Summarize
- Recommend action

---

# Platform Status

Monitoring:

- Backend
- AI Provider
- Security tools
- Integration status

---

# 16. SOC Analyst Workflow

## Alert Handling

```
Detection

↓

Triage

↓

Investigation

↓

Classification

↓

Response

↓

Closure
```

---

# 17. AI Security Assistant Workflow

AI membantu:

## Alert Explanation

Contoh:

```
Why suspicious?

1.
Unknown executable

2.
Network communication

3.
Abnormal user behavior
```

---

## Investigation

AI mencari:

- Related events
- Similar activity
- Historical behavior

---

# 18. Threat Intelligence Workflow

```
IOC Found

↓

Lookup Intelligence

↓

Check Asset

↓

Determine Impact

↓

Response
```

---

# 19. Performance Optimization

Untuk deployment besar:

## Elasticsearch

Gunakan:

- Index lifecycle
- Proper shard
- Aggregation

---

## Backend

Gunakan:

- Async processing
- Cache
- Worker queue

---

## AI

Gunakan:

- Context limitation
- Streaming response
- Token control

---

# 20. Security Hardening

## Application Security

Implement:

- Authentication
- Authorization
- RBAC
- Audit logging

---

## Network Security

Recommended:

- TLS
- Firewall
- VPN
- Restricted access

---

## Secret Management

Jangan simpan:

```
API KEY

TOKEN

PASSWORD
```

di source code.

---

# 21. Monitoring and Maintenance

Monitor:

```
CPU

Memory

Disk

Indexer Health

API Latency

AI Availability

Queue Size
```

---

# 22. Troubleshooting

## Dashboard kosong

Check:

```
Backend

Indexer

Authentication

Network
```

---

## AI tidak response

Check:

```bash
curl AI_PROVIDER_BASE_URL
```

---

## Query lambat

Check:

- Index size
- Query pattern
- Aggregation
- Cache

---

# 23. Backup and Recovery

Backup:

```
Configuration

Environment File

Security Index

Dashboard Configuration
```

---

# 24. Upgrade Procedure

Before upgrade:

```
Backup

↓

Stop Service

↓

Update Code

↓

Install Dependency

↓

Restart

↓

Validation
```

---

# 25. Developer Guide

Structure:

```
wazuh-mcp-unified

|

├── server.py

├── soc_automation.py

├── static/

│

├── index.html

├── app.js

├── styles.css

|

├── requirements.txt

|

└── docker-compose.yml

```

---

# 26. API Overview

Typical API:

```
GET

/dashboard

GET

/alerts

GET

/findings

POST

/ai-analysis

GET

/platform/status

```

---

# 27. Production Deployment Recommendation

Enterprise architecture:

```
Load Balancer

       |

SOC Dashboard

       |

Backend Cluster

       |

Worker Queue

       |

Security Data Layer

       |

Wazuh Cluster

```

---

# 28. Future Development Roadmap

## Phase 1

SOC Foundation

- Incident management
- Case tracking
- Evidence management
- Risk scoring

---

## Phase 2

Advanced SOC

- UEBA
- Correlation Engine
- Threat Hunting Workspace
- SOAR

---

## Phase 3

AI SOC

- Autonomous investigation
- AI detection engineering
- Automated response

---

# 29. Conclusion

Wazuh MCP Unified bukan hanya dashboard monitoring.

Platform ini dirancang menjadi:

```
Security Detection

        |

Context Enrichment

        |

AI Investigation

        |

Human Decision

        |

Security Response

        |

Continuous Improvement
```

Tujuan akhir:

Membangun SOC modern yang:

- lebih cepat melakukan investigasi,
- mengurangi manual effort,
- meningkatkan visibility,
- membantu analyst mengambil keputusan berdasarkan data.

---

# End of Documentation
