
from setuptools import setup, find_packages

setup(
    name='satellite-defense-toolkit',
    version='1.0.0',
    url='https://github.com/your-org/satellite-defense-toolkit',
    include_package_data=True,
    install_requires=[
        "stix2>=3.0.1",
        "taxii2-client>=2.3.0",
        "matplotlib>=3.8.0",
        "scapy>=2.5.0",
        "yara-python>=4.3.1",
        "tensorflow>=2.14.0",
        "flask>=2.2.5",
        "websocket-client>=1.7.0",
        "psutil>=5.9.0",
        "rich>=13.6.0",
    ],
    entry_points={
        'console_scripts': [
            'satdef-toolkit = launcher.satellite_defense_toolkit_launcher:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires='>=3.8',
)
