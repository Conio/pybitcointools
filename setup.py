#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='conio-bitcoin',
      version='1.0.22',
      description='Python Bitcoin Tools',
      author='Vitalik Buterin',
      author_email='vbuterin@gmail.com',
      url='http://github.com/vbuterin/pybitcointools',
      packages=['bitcoin'],
      scripts=['pybtctool'],
      include_package_data=True,
      data_files=[("", ["LICENSE"]), ("bitcoin", ["bitcoin/english.txt"])],
      )
