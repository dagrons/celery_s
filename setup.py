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
        'celery',
        'mongoengine',
        'mtools @ git+https://github.com/dagrons/mtools@master',
        'fcommon @ git+https://github.com/dagrons/fcommon@master',
        'py2neo',
        'pymongo',
        'redis',
        'requests',
        'python-dotenv',
        'flower',
    ]
)
