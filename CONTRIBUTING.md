# Contributing to CloudDrift

We welcome community contributions.

## Development Setup

1. Clone repository:
   ```bash
   git clone https://github.com/csenta/cloud-drift.git
   cd cloud-drift
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run tests before submitting pull requests:
   ```bash
   PYTHONPATH=. python3 -m unittest discover -s tests -v
   ```
4. Follow PEP 8 guidelines and write comprehensive unit tests for all new compliance rules and resource parsers.
