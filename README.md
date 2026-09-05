# Merkle Mountain Range Mmr

> **Domain:** Clinical Decision Support & Biomedical Computing  
> **Reference Guidelines & Standards:** `Standard Clinical Formulations & ISO/IEC Quality Frameworks`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

**Merkle Mountain Range Mmr** is an advanced analytical and computational platform implementing Merkle Mountain Range (MMR) dynamic append-only cryptographic accumulator. It provides multi-agent consensus evaluation with tamper-evident audit logging and zero-PHI outbound protection.

---

## ⚙️ Key Capabilities & Algorithmic Modules

- **Deterministic Calculation Engine**: Strict compliance with standard reference formulations and thresholds.
- **Risk & Urgency Classification**: Multi-tier categorization with automated clinical/operational action recommendations.
- **Validation & Guardrails**: Rigorous input bounds checking and anomaly detection.
- **Multi-Agent Consensus**: Specialized workers (InvariantQC, SafetyEscalation, ProtocolConformance) evaluate tasks independently.

---

## 💻 CLI Quickstart & Usage

### Installation
```bash
pip install -e .
```

### 1. Single Task Evaluation
```bash
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --critical --status DISCORDANT
```

### 2. Batch Processing (CSV)
```bash
python cli.py batch -i sample.csv -o results.csv
```

### 3. System Chat Query
```bash
python cli.py chat "What is the system status?"
```

### 4. Verify Audit Trail Integrity
```bash
python cli.py verify-audit
```

### 5. Launch REST API Server
```bash
python cli.py serve --host 127.0.0.1 --port 8000
```

### Parameter Reference
| Parameter | Description | Default |
|:----------|:------------|:--------|
| `--task-id` | Unique task/case identifier | TASK-2026-001 |
| `--target` | Target entity or specimen key | KEY-TARGET-01 |
| `--primary` | Primary measurement value (float) | 28.5 |
| `--secondary` | Secondary metric value (float) | 14.2 |
| `--critical` | Flag as critical/emergency | False |
| `--status` | Status descriptor | DISCORDANT |

### Input Data Schema (CSV)

| Field | Description | Requirement |
|:------|:------------|:------------|
| `task_id` | Unique task identifier | Required |
| `target_identifier` | Target entity key | Required |
| `primary_metric` | Primary measurement (float) | Required |
| `secondary_metric` | Secondary metric (float) | Required |
| `is_critical_flag` | Critical flag (True/False) | Required |
| `status_descriptor` | Status code | Required |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers. Applied to all inputs including batch CSV processing.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs with full signature verification for every evaluation and state transition.
* **Input Validation:** Rejects NaN, infinite, and empty values to prevent sensor/algorithm fault propagation.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

### Security Configuration

Set a cryptographically secure audit key before production deployment:

```bash
# Linux/macOS
export AUDIT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Windows PowerShell
$env:AUDIT_SECRET_KEY = -join ((1..32 | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) }))
```

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py 1000
```

---

## 🐳 Container Deployment

### Docker
```bash
docker build -t merkle-mountain-range-mmr .
docker run -p 8000:8000 -e AUDIT_SECRET_KEY=your-secret-key merkle-mountain-range-mmr
```

### Docker Compose
```bash
# Create .env file with your secret key
echo "AUDIT_SECRET_KEY=your-secret-key" > .env

# Start the service
docker-compose up -d
```

---

## 📁 Project Structure

```
merkle-mountain-range-mmr/
├── agents/                    # Core agent system
│   ├── base.py               # Security, PHI guard, audit trail
│   ├── models.py             # Pydantic data models
│   ├── supervisor.py         # Multi-agent orchestrator
│   ├── workers.py            # Specialized evaluation workers
│   ├── api.py                # FastAPI REST endpoints
│   └── ...
├── merkle_mountain_range/    # Alternative MMR implementation
├── tests/                    # Test suite
├── cli.py                    # Command-line interface
├── simulator.py              # High-throughput simulation
├── web/                      # Operations console (HTML)
├── Dockerfile                # Container definition
└── docker-compose.yml        # Multi-container orchestration
```
