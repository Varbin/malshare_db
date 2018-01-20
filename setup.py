"""
Installation script of malshare_db.

Usage (pip):
    pip install .

Usage (direct):
    setup.py build  # "Build" + Checkup
    setup.py install  # Installation
"""

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
    print("Warning: setuptools not found! Falling back to raw distutils.")
    print(" -> This may not properly register packages with python.")
    print(" -> Script installation not available.")
    print("")

import re

with open('malshare_db.py') as malshare_db:
    code = malshare_db.read()

metadata = dict(re.findall("__([a-z]+)__ = '([^']+)'", code))

setup(
    author=metadata.get('author'),
    author_email=metadata.get('email'),
    license=metadata.get('license'),
    name="malshare_db",
    url='https://sbiewald.de/malsh-cav',
    version=metadata.get('version'),

    py_modules=['malshare_db'],
    entry_points = {
        'console_scripts': ['malshare-db=malshare_db:main'],
    },
)
