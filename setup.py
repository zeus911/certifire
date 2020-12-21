#!/usr/bin/env python

import certifire
import certifire.plugins.acme
import certifire.plugins.dns_providers
from codecs import open
from setuptools import setup, find_packages
import sys

try:
    # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError:
    # for pip <= 9.0.3
    print("error: Upgrade to a pip version newer than 10. Run \"pip install "
          "--upgrade pip\".")
    sys.exit(1)

with open("README.md", "r") as fh:
    long_description = fh.read()


# Solution from http://bit.ly/29Yl8VN
def resolve_requires(requirements_file):
    try:
        requirements = parse_requirements("./%s" % requirements_file,
                                          session=False)
        return [str(ir.req) for ir in requirements]
    except AttributeError:
        # for pip >= 20.1.x
        # Need to run again as the first run was ruined by the exception
        requirements = parse_requirements("./%s" % requirements_file,
                                          session=False)
        # pr stands for parsed_requirement
        return [str(pr.requirement) for pr in requirements]


setup(
    name="certifire",
    version=certifire.get_version(),
    license=certifire.__licence__,
    description=("Certifire Minimal - Automate Certificates from let'sencrypt"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/certi-fire/certifire",
    author=certifire.get_author(),
    author_email=certifire.get_author_email(),
    classifiers=[
        "Development Status :: 1 - Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3 :: Only",
    ],
    packages=find_packages(),
    install_requires=resolve_requires("requirements.txt"),
    entry_points={
        'console_scripts': [
            "certifire = certifire.cli:certifire_main",
            "certifire-manager = certifire.manage:main",
        ],
    },
)
