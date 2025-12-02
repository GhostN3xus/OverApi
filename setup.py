#!/usr/bin/env python3
"""
OverApi - Universal API Security Scanner
Setup configuration for installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="overapi",
    version="1.0.0",
    author="OverApi Team",
    author_email="security@overapi.dev",
    description="Universal API Security Scanner - Comprehensive offensive & defensive API testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/GhostN3xus/OverApi",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "overapi=overapi.cli:main",
            "overapi-gui=overapi.gui:main",
        ],
    },
    include_package_data=True,
    package_data={
        "overapi": [
            "data/*.txt",
            "data/*.json",
        ],
    },
    keywords=[
        "security",
        "api",
        "scanner",
        "pentest",
        "security-testing",
        "rest-api",
        "graphql",
        "soap",
        "grpc",
        "websocket",
        "owasp",
        "vulnerability-scanner",
    ],
    project_urls={
        "Bug Reports": "https://github.com/GhostN3xus/OverApi/issues",
        "Source": "https://github.com/GhostN3xus/OverApi",
        "Documentation": "https://github.com/GhostN3xus/OverApi/wiki",
    },
)
