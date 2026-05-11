# Mini SIEM Capstone Project

## Overview
This project implements a lightweight Security Information and Event Management (SIEM) system capable of ingesting, normalizing, correlating, detecting, and visualizing cybersecurity activity using real-world Los Alamos National Laboratory (LANL) datasets.

## Features
- Multi-source log ingestion
- Event normalization
- Behavioral correlation
- Time-based detection rules
- Alert generation
- Flask dashboard visualization
- Red team validation

## Technologies Used
- Python
- Flask
- SQLite
- JSON / JSONL
- Chart.js
- GitHub

## Project Structure
- `ingest/` → log ingestion scripts
- `normalize/` → event normalization
- `detect/` → detection logic
- `storage/` → SQLite database operations
- `templates/` → Flask dashboard HTML
- `static/` → CSS styling
- `data/` → sample datasets and alerts

## Running the Project
Run:

```bash
python app.py
