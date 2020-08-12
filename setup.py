from setuptools import setup
from os import path

currrent_direct = path.abspath(path.dirname(__file__))
with open(path.join(currrent_direct, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='CrowdClient',
    version='0.2.7',
    packages=['CrowdClient'],
    url='https://github.com/tyler-tee/CrowdClient',
    license='GPLv3',
    author='Tyler Talaga',
    author_email='ttalaga@wgu.edu',
    description='CrowdClient is a Python library for interacting with CrowdStrike Falcon\'s REST API.',
    long_description=long_description,
    long_description_content_type='text/markdown'
)
