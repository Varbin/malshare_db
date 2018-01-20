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
    name="malshare_db",
    version=metadata.get('version'),

    author=metadata.get('author'),
    author_email=metadata.get('email'),
    license=metadata.get('license'),
    url='https://sbiewald.de/malsh-cav',

    py_modules=['malshare_db'],
    entry_points={
        'console_scripts': ['malshare-db=malshare_db:main'],
    },
    
    classifiers=[
        'Framework :: AsyncIO',
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Security',
    ]
)
