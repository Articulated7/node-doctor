# Contributing to Node Doctor

Thank you for your interest in contributing to Node Doctor! This project aims to help Tor relay operators maintain secure and properly configured relays.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion:

1. Check if the issue already exists in GitHub Issues
2. If not, create a new issue with:
   - Clear description of the problem or suggestion
   - Steps to reproduce (for bugs)
   - Your environment (OS, Python version, Tor version)

### Suggesting New Checks

We're always looking for new security checks to add. When suggesting a check:

1. Explain what misconfiguration or security issue it detects
2. Describe why it's important
3. Provide examples of what "pass" and "fail" look like
4. Note any special requirements (sudo access, external connections, etc.)

### Contributing Code

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Make your changes
4. Write tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Run code formatting (`black .`)
7. Submit a pull request

### Code Style

- We use `black` for code formatting
- Follow PEP 8 guidelines
- Add docstrings to all functions and classes
- Keep functions focused and small
- Comment complex logic

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/node-doctor.git
cd node-doctor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install package in development mode
pip install -e .

# Run tests
pytest

# Format code
black .
