# TRACER Network Path Analysis Tool

**Version 0.2** - Interactive network forensics and path analysis for cybersecurity incident response.

> 📋 **Important**: This tool implements the [TRACER Framework](FRAMEWORK.md) - a comprehensive methodology for network-based threat intelligence. Understanding the framework is essential for effective use of this tool.

## Overview

TRACER is a network path analysis tool designed for cybersecurity professionals conducting incident response and forensic investigations. It helps map network traffic paths from source to destination, documenting all network appliances and their configurations along the way.

**Key Features:**
- 🖥️ **Dual Interface**: Command-line tool and REST API
- ☁️ **Flexible Storage**: Local JSON files or MongoDB Atlas cloud storage
- 🐳 **Container Ready**: Docker deployment for production environments
- 📊 **Rich Documentation**: Detailed case analysis and reporting
- 🔗 **Integration Friendly**: REST API for automation and SIEM integration

## Quick Start

### CLI Mode (Interactive Analysis)

```bash
# Clone the repository
git clone https://github.com/steveinit/TRACER-framework.git
cd TRACER-framework

# Run the interactive CLI
python3 tracer.py
```

### API Mode (Production/Integration)

```bash
# Setup virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure storage (optional)
cp .env.example .env
# Edit .env with your MongoDB Atlas credentials if desired

# Start the API server
python api.py
```

The API will be available at `http://localhost:8000` with interactive documentation at `http://localhost:8000/docs`.

### Docker Deployment

```bash
# JSON storage (lightweight)
docker-compose -f docker-compose.json.yml up

# MongoDB Atlas (production)
docker-compose -f docker-compose.atlas.yml up

# Local MongoDB (development)
docker-compose up
```

## Example Analysis

Here's how TRACER documents a network path during incident investigation:

```
============================================================
TRACER Analysis Report - SQL Injection Attack
============================================================

Case ID: CASE_20240929_125453
Threat Type: SQL Injection
Source: 192.168.1.100 → Destination: 10.0.0.50

--- COMPLETE NETWORK PATH ---
SOURCE: 192.168.1.100
  ↓
ASA-5525 (FIREWALL) - Direct Traversal
    Source → interface: GigabitEthernet0/1
    Dest → interface: GigabitEthernet0/2
    Dest → ACL_rule: permit tcp any host 10.0.0.50 eq 80
  ↓
Catalyst-3850 (SWITCH) - Direct Traversal
    Source → port: Gi1/0/24
    Source → CAM_entry: 0025.64FF.EE12
    Dest → port: Gi1/0/12
    Dest → VLAN: 100
  ↓
DESTINATION: 10.0.0.50

--- ANALYSIS SUMMARY ---
Direct Traversals: 2
Lateral Movements: 0
Pivot Points: 0
```

## Why Use TRACER?

**For Security Teams:**
- **Standardized Documentation**: Consistent network forensics format
- **Incident Response**: Rapid network path mapping during active threats
- **Team Collaboration**: Shareable case files and reports
- **Integration Ready**: REST API for SIEM and automation tools

**For Network Engineers:**
- **Visibility**: Clear documentation of traffic flows through infrastructure
- **Troubleshooting**: Network path verification and validation
- **Change Management**: Before/after network path comparison

## Storage Options

TRACER automatically detects and configures storage based on your environment:

| Storage Type | Use Case | Setup |
|-------------|----------|-------|
| **JSON Files** | Development, small teams | No configuration needed |
| **MongoDB Atlas** | Production, team collaboration | Set `MONGODB_URL` environment variable |
| **Local MongoDB** | Development with cloud features | Use Docker Compose |

## REST API

The TRACER API provides programmatic access for automation and integration:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/cases` | GET | List all cases |
| `/cases` | POST | Create new case |
| `/cases/{id}` | GET | Get case details |
| `/cases/{id}/elements` | POST | Add network element |
| `/cases/{id}/report` | GET | Generate analysis report |

## Documentation

- **[Setup Guide](SETUP.md)** - Detailed installation and deployment instructions
- **[TRACER Framework](FRAMEWORK.md)** - Understanding the methodology (essential reading)
- **[Development Roadmap](ROADMAP.md)** - Project status and future plans

## Requirements

- **Python 3.11+** (CLI and API modes)
- **Docker** (optional, for containerized deployment)
- **MongoDB Atlas account** (optional, for cloud storage)

## Integration Examples

**SIEM Integration:**
```bash
# Create case from security alert
curl -X POST http://localhost:8000/cases \
  -d '{"initial_detection": {"threat_type": "SQL Injection", "source_ip": "1.2.3.4", "destination_ip": "5.6.7.8"}}'
```

**Automation Workflows:**
- ExtraHop detection → n8n → TRACER case creation
- Splunk alert → Python script → TRACER analysis
- SOC ticket → API call → Network path documentation

## Contributing

We welcome contributions! Please:

1. **Test with real network scenarios** - Break it and report issues
2. **Share workflow feedback** - How does TRACER fit your SOC processes?
3. **Submit issues** at https://github.com/steveinit/TRACER-framework/issues

## Support

- **Issues & Bug Reports**: [GitHub Issues](https://github.com/steveinit/TRACER-framework/issues)
- **Documentation Questions**: See [SETUP.md](SETUP.md) for detailed configuration
- **Framework Questions**: Read [FRAMEWORK.md](FRAMEWORK.md) for methodology guidance

---

**Trust → Recognize → Analyze → Communicate → Engage → Refine**

*TRACER v0.2 - Network forensics done right.*