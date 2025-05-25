# PITO (P2P share system)

A secure peer-to-peer file sharing application with a modern GUI interface, built using Python, FastAPI, and PyQt5.

## Features

- Modern PyQt5-based graphical user interface
- FastAPI backend for efficient file transfer
- Secure TLS/SSL encrypted communication
- Automatic peer discovery using Zeroconf
- Cross-platform support
- Real-time file synchronization
- Secure certificate management

## Requirements

- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/p2pshare.git
cd p2pshare
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Unix or MacOS:
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python main.py
```

2. The application will:
   - Generate necessary TLS certificates if they don't exist
   - Start the backend server
   - Launch the GUI interface
   - Automatically discover other peers on the network

## Project Structure

- `main.py` - Application entry point
- `backend/` - FastAPI server implementation
- `gui/` - PyQt5 GUI implementation
- `shared/` - Shared utilities and configurations
- `tests/` - Test suite
- `certs/` - TLS certificate storage
- `logs/` - Application logs

## Development

### Running Tests

```bash
pytest
```

For test coverage report:
```bash
pytest --cov=.
```

### Code Style

The project follows PEP 8 style guidelines. Consider using tools like `black` and `flake8` for code formatting and linting.

## Security

- All communication is encrypted using TLS/SSL
- Certificates are automatically generated and managed
- No central server required - direct peer-to-peer communication

## License

[Add your chosen license here]

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
