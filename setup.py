#!/usr/bin/env python3
"""
SNIFF - Network Packet Capture Tool
Setup script for pip installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="sniff-pcap",
    version="0.0.1",
    description="Network packet capture tool with real-time TUI and modular analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Tu",
    author_email="ntu168108@gmail.com",
    url="https://github.com/ntu168108/sniff",
    license="MIT",
    
    # Package configuration
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*"]),
    include_package_data=True,
    
    # Python version requirement
    python_requires=">=3.8",
    
    # Dependencies
    install_requires=[
        "scapy>=2.5.0",
    ],
    
    # Entry points - this creates the 'sniff' command
    entry_points={
        "console_scripts": [
            "sniff=sniff:main",
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
    ],
    
    # Keywords
    keywords="packet sniffer network capture pcap security monitoring",
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/ntu168108/sniff/issues",
        "Source": "https://github.com/ntu168108/sniff",
    },
)
