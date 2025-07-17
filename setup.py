#!/usr/bin/env python3
# File: setup.py

from setuptools import setup, find_packages
from pathlib import Path

def read_long_description():
    try:
        return Path("README.md").read_text(encoding="utf-8")
    except Exception:
        return "Advanced Satellite and Aerospace Cybersecurity Framework: Red Team, Forensics, Defense, and C2"

def parse_requirements():
    try:
        return Path("requirements.txt").read_text().splitlines()
    except FileNotFoundError:
        return [
            "websocket-client>=1.7.0",
            "flask>=2.2.5",
            "flask-socketio>=5.3.0",
            "rich>=13.6.0",
            "psutil>=5.9.0",
            "stix2>=3.0.1",
            "yara-python>=4.3.1",
            "scapy>=2.5.0",
            "numpy>=1.24.0",
            "Pillow>=10.0.0",
            "pyyaml>=6.0.1",
            "pyserial>=3.5",
            "aioblescan>=0.2.10",
            "blesuite>=0.1.10",
            "vosk>=0.3.45",
            "pyttsx3>=2.90",
            "torch>=2.1.0",
            "torchaudio>=2.1.0",
            "tensorflow>=2.14.0",
            "transformers>=4.33.0",
            "opencv-python>=4.8.0",
            "openai>=1.10.0"
        ]

setup(
    name='satellite-defense-toolkit',
    version='1.0.1',
    description='Advanced Satellite and Aerospace Cybersecurity Framework: Red Team, Forensics, Defense, and C2',
    long_description=read_long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/s0m3on35/satellite-defense-tookit',
    packages=find_packages(exclude=["tests", "examples"]),
    include_package_data=True,
    install_requires=parse_requirements(),
    entry_points={
        'console_scripts': [
            'satdef-cli = satellite_defense_toolkit_cli:main',
            'satdef-gui = satellite_defense_toolkit_gui:main'
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Utilities",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires='>=3.8',
    keywords='satellite cybersecurity GNSS C2 red-team forensics AI aerospace defense SDR telemetry CLI GUI',
)
