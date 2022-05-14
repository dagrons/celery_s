from distutils.core import setup

import setuptools

setup(
    name="celery_s",
    version="1.0",
    description="celery service for malware analysis",
    author="dagrons",
    author_email="heyuehuii@126.com",
    packages=setuptools.find_packages(),
    include_package_data=True,
    install_requires=[
        'celery==5.1.2',
        'mongoengine==0.23.1',
        'mtools @ git+https://github.com/dagrons/mtools@master',
        'py2neo==2021.1.5',
        'pymongo==3.11.4',
        'redis==3.5.3',
        'requests==2.27.1',
        'dotenv'
    ]
)
