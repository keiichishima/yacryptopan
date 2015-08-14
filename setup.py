#!/usr/bin/env python

from __future__ import print_function

from setuptools import setup

try:
    from pypandoc import convert
    read_md = lambda f: convert(f, 'rst')
except ImportError:
    print('pandoc is not installed.')
    read_md = lambda f: open(f, 'r').read()

setup(name='yacryptopan',
      version='0.0.1',
      description='Yet another Crypto-PAn implementation for Python',
      long_description=read_md('README.md'),
      author='Keiichi SHIMA',
      author_email='keiichi@iijlab.net',
      py_modules=['yacryptopan'],
      install_requires=['pycrypto>=2.6.1', 'netaddr>=0.7.15'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Intended Audience :: Information Technology',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2.7',
          'Topic :: Scientific/Engineering :: Information Analysis',
          'Topic :: Security :: Cryptography',
          'Topic :: Software Development :: Libraries :: Python Modules'],
      license='BSD License',
     )
