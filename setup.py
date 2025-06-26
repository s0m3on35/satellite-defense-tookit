
from setuptools import setup

setup(
    name='satellite-defense-toolkit',
    version='0.1',
    py_modules=['satellite_defense_toolkit_launcher'],
    install_requires=[],
    entry_points={
        'console_scripts': [
            'satdef-toolkit = satellite_defense_toolkit_launcher:main',
        ],
    },
)
