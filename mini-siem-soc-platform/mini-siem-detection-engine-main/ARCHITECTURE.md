# System Architecture

## High-Level Diagram
```mermaid
graph TD
    subgraph Red Team
    A[Attack Scripts] -->|Gen Logs| B(Raw Logs)
    end

    subgraph Blue Team / Engine
    B -->|Stream| C[Ingest Layer]
    C -->|Raw String| D[Parser]
    D -->|Dict| E[Normalizer]
    E -->|Normalized Event| F[Detection Engine]
    F -->|Raw Alert| G[Correlation Engine]
    G -->|Bundled Incident| H[Alert Output]
    end

    subgraph Dashboard
    H -->|alerts.json| I[HTML UI]
    end
```

## Components

### 1. Ingestion & Normalization (`engine/ingest.py`, `engine/normalize.py`)
- **Ingest**: Reads file streams or batches.
- **Parser**: Regex/JSON parsing.
- **Normalizer**: Maps to standard fields: `event_type`, `user`, `src_ip`, `action`, `resource`.

### 2. Detection Engine (`engine/detector.py`)
- Loops through YAML rules in `detections/`.
- Checks `condition` against normalized events.
- Skips if `false_positives` match.

### 3. Correlation Engine (`engine/correlator.py`)
- **Time-Window Logic**: Aggregates alerts within a sliding window (e.g., 5 mins).
- **Sequence Detection**: Detects patterns like "Failed Login" x5 -> "Success".

### 4. Data Storage
- **Logs**: `logs/*.log`
- **Alerts**: `alerts/alerts.json`
