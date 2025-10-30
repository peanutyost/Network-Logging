# Network Traffic DNS Logger

A comprehensive network monitoring application that captures all network traffic, extracts DNS queries, logs them to a database, and provides a web-based UI with analytics and threat hunting tools.

## Features

- **Packet Capture**: Captures all network traffic on Linux using scapy
- **DNS Logging**: Extracts and logs all DNS queries and responses to database
- **Traffic Monitoring**: Tracks traffic flows and data volumes to destinations
- **Orphaned IP Detection**: Identifies IPs with traffic but no DNS entry
- **Web Dashboard**: Vue.js frontend with real-time statistics and charts
- **Threat Hunting**: Tools for analyzing network anomalies
- **Database Support**: PostgreSQL (default) with SQLite alternative

## Architecture

- **Packet Capture Service**: Captures network packets and extracts DNS/traffic data
- **FastAPI Backend**: REST API for data access
- **Vue.js Frontend**: Modern web UI with charts and analytics
- **PostgreSQL Database**: Stores DNS lookups and traffic flows

## Prerequisites

- Docker and Docker Compose
- Linux system with packet capture capabilities
- Network interface permissions for packet capture

## Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd network-logging
```

2. Copy environment file:
```bash
cp env.sample .env
```

3. Edit `.env` to configure ports, database, etc.

4. Start services:
```bash
docker-compose up -d
```

5. Access the web UI at `http://localhost:3000`
6. API documentation at `http://localhost:8000/docs`

## Configuration

### Environment Variables

- `DB_TYPE`: Database type (`postgresql` or `sqlite`)
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`: Database connection
- `CAPTURE_PORTS`: Comma-separated list of ports to monitor (empty for all)
- `CAPTURE_INTERFACE`: Network interface to capture on (empty for default)
- `LOG_LEVEL`: Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`)
- `ORPHANED_IP_DAYS`: Days to look back for DNS match (default: 7)

## Services

### Capture Service
Captures network traffic and logs DNS queries and traffic flows. Requires `NET_ADMIN` and `NET_RAW` capabilities.

### API Service
FastAPI backend providing REST endpoints for:
- DNS search and lookup
- Traffic analytics
- Dashboard statistics
- Threat hunting queries

### Web UI Service
Vue.js frontend with:
- Dashboard with key metrics
- Domain search interface
- Traffic volume charts
- Orphaned IP viewer
- Top domains analytics

### Database Service
PostgreSQL database storing:
- DNS lookups with resolved IPs
- Traffic flow statistics
- Threat indicators

## API Endpoints

- `GET /api/dashboard/stats` - Dashboard statistics
- `GET /api/dns/search?query={query}` - Search domains
- `GET /api/dns/domain/{domain}` - Get domain info
- `GET /api/traffic/domain/{domain}` - Get traffic for domain
- `GET /api/traffic/top-domains` - Top domains by traffic
- `GET /api/threat/orphaned-ips?days={days}` - Orphaned IPs

## Development

### Python Dependencies
```bash
pip install -r requirements.txt
```

### Frontend Dependencies
```bash
cd webui
npm install
npm run dev
```

### Running Locally
1. Start PostgreSQL:
```bash
docker-compose up -d postgres
```

2. Run capture service:
```bash
python main.py
```

3. Run API:
```bash
uvicorn api.app:app --reload
```

4. Run frontend:
```bash
cd webui
npm run dev
```

## Notes

- Packet capture requires root or `NET_ADMIN` capabilities on Linux
- The capture service uses host network mode for packet capture
- Ensure sufficient disk space for traffic logs
- For production, configure proper CORS origins in API

## License

MIT License

