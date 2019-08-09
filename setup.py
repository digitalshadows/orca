#!/usr/bin/env python
import os
from setuptools import setup, find_packages


def get_version():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    return open(os.path.join(root_dir, 'VERSION')).read().strip()


with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='orca-recon',
    version=get_version(),
    python_requires='>=3.6',
    description=(
        'A Python CLI tool for enumerating network infrastructure.'
    ),
    long_description='A Python CLI tool for enumerating network infrastructure.',
    install_requires=requirements,
    include_package_data=True,
    author='Photon Research Team',
    author_email='support@digitalshadows.com',
    license='Copyright (c) 2019 Digital Shadows Ltd',
    copyright='Copyright (c) 2019 Digital Shadows Ltd',
    packages=find_packages(),
    entry_points = {
        'console_scripts': ['orca-recon=orca.orcarecon:cli'],
    },
    url="https://www.digitalshadows.com/",
    platforms="linux",
)