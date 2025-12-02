# Installation and Setup Guide

## System Requirements

- **Python**: 3.10 or higher
- **OS**: Linux, macOS, or Windows
- **RAM**: Minimum 512MB, recommended 2GB+
- **Disk Space**: 100MB for installation

## Step-by-Step Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd OverApi
```

### 2. Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python main.py --help
```

You should see the OverApi banner and help menu.

## Quick Start

### Basic Scan

```bash
python main.py --url https://api.example.com --out report.html
```

### With All Features

```bash
python main.py --url https://api.example.com \
    --mode aggressive \
    --threads 20 \
    --out report.html \
    --json report.json \
    --verbose
```

## Creating Standalone Executable with PyInstaller

### Step 1: Install PyInstaller

```bash
pip install pyinstaller
```

### Step 2: Create Executable

```bash
pyinstaller --onefile \
    --name overapi \
    --icon=icon.ico \
    --add-data "overapi:overapi" \
    main.py
```

### Step 3: Locate Executable

The executable will be in the `dist/` directory:

```bash
./dist/overapi --help
```

### Step 4: Use Standalone Executable

```bash
./dist/overapi --url https://api.example.com --out report.html
```

## Docker Setup (Optional)

Create a `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENTRYPOINT ["python", "main.py"]
```

Build and run:

```bash
docker build -t overapi .
docker run --rm overapi --url https://api.example.com --out report.html
```

## Virtual Environment Setup

### Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Deactivate Virtual Environment

```bash
deactivate
```

## Troubleshooting

### Import Errors

If you get import errors, ensure you're in the correct directory:

```bash
cd /path/to/OverApi
source venv/bin/activate
python main.py --url ...
```

### SSL Certificate Issues

```bash
python main.py --url https://api.example.com --no-verify-ssl
```

### Permission Denied

```bash
chmod +x main.py
python main.py --help
```

### Python Version Check

```bash
python --version  # Should be 3.10+
python3 --version
```

## Environment Variables

You can set environment variables for proxy or other settings:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
python main.py --url https://api.example.com
```

## Updating OverApi

```bash
cd OverApi
git pull origin main
pip install -r requirements.txt --upgrade
```

## Uninstalling

```bash
# Deactivate virtual environment
deactivate

# Remove virtual environment
rm -rf venv

# Or remove the entire OverApi directory
rm -rf OverApi
```

## Platform-Specific Notes

### Linux/macOS

```bash
chmod +x main.py
./main.py --help  # If hashbang is set
# or
python main.py --help
```

### Windows

```cmd
python main.py --help
# For standalone: overapi.exe --help
```

## Support

For issues during installation:

1. Verify Python version: `python --version`
2. Check requirements are installed: `pip list`
3. Try reinstalling dependencies: `pip install -r requirements.txt --force-reinstall`
4. Check network connectivity for package downloads
5. Try using a virtual environment

## Next Steps

After installation, refer to the main README.md for usage examples and API type-specific scanning instructions.
