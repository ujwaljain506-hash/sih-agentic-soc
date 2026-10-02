# AI-Agentic SOC SIEM

A smart, autonomous Security Operations Center built to detect suspicious log events, classify threat severity, and generate immediate executable remediation commands using AI and multi-agent orchestration.

This project was developed for a Smart India Hackathon and demonstrates how LLM-powered SOC workflows can reduce analyst workload, detect attack patterns faster, and support real-time incident response.

## Problem Statement

Traditional SIEM systems often depend on static rules and manual triage, which slows down response during active cyber incidents. Security teams need a system that can:

- ingest logs from multiple sources
- identify suspicious behavior in real time
- determine risk levels quickly
- suggest or execute actionable remediation steps immediately

## Solution Overview

This solution combines:

- log ingestion from Linux and Windows event sources
- AI-based analysis using LangGraph and Groq models
- risk classification and reasoning generation
- remediation command generation tailored to the log source
- a dashboard for monitoring and investigation
- REST APIs for integration and querying

## Key Features

- Autonomous threat triage for Linux authentication and Windows Sysmon logs
- Severity evaluation for suspicious events
- OS-specific remediation command generation
- Real-time monitoring loop for incoming logs
- SQLite-backed storage for event and verdict persistence
- Streamlit dashboard for security visibility
- FastAPI backend for ingestion and querying
- Dockerized deployment for easy setup and reproducibility

## Architecture

The system follows a modular architecture with separate components for:

1. Log ingestion
2. Threat assessment using AI agents
3. Remediation response generation
4. Storage and retrieval
5. Visualization and API access

### Tech Stack

- Python
- LangGraph
- LangChain
- Groq LLM
- FastAPI
- Streamlit
- Plotly
- SQLite
- Docker / Docker Compose

## Workflow

1. Security logs are ingested into the system.
2. The AI agent analyzes the event context, source, and metadata.
3. The system classifies whether the activity is suspicious and assigns a threat level.
4. An incident response node generates a remediation command based on the source type.
5. Results are stored and shown in the dashboard.

## Project Structure

```bash
sih-agentic-soc/
├── agent.py                 # AI orchestration and SOC agent workflow
├── api.py                  # FastAPI backend
├── dashboard.py            # Streamlit dashboard UI
├── database.py             # SQLite database logic
├── ingestion.py            # Log collection / ingestion pipeline
├── parser.py               # Log parsing logic
├── sysmon_parser.py        # Windows Sysmon parsing
├── query_db.py             # Query utility for database inspection
├── simulate_attacks.py     # Attack simulation script
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container build
├── docker-compose.yml      # Multi-service deployment
├── sample_logs/
│   └── sysmon.json
├── schema.md               # Database/schema documentation
├── .env.example            # Environment variable template (if present)
└── readme.md               # Project documentation
```

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/your-username/sih-agentic-soc.git
cd sih-agentic-soc
```

### 2. Configure environment variables

Create a `.env` file in the root directory:

```env
GROQ_API_KEY=your_groq_api_key_here
WEBHOOK_URL=your_discord_or_slack_webhook_url_here
```

### 3. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Run the services

```bash
python3 ingestion.py
python3 agent.py
streamlit run dashboard.py
uvicorn api:app --port 8001
```

## Docker Deployment

```bash
docker compose up -d --build
```

After startup:

- Dashboard: http://localhost:8501
- API Docs: http://localhost:8001/docs

## Use Cases

- real-time SOC monitoring
- analyst decision support
- automated response suggestions
- cyber defense demonstrations
- hackathon prototyping for AI-powered security workflows

## Future Enhancements

- add more log sources and parsers
- integrate MITRE ATT&CK mapping
- enhance decision explainability
- support automated containment actions with role-based permissions
- connect to SIEM platforms such as Splunk or Elastic

## Team / Author

Ujwal Jain

## License

This project is provided for educational and hackathon demonstration purposes.
