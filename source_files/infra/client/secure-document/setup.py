# setup.py
from setuptools import setup, find_packages

setup(
    name="secure-document",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.4.7",
    ],
    entry_points={
        "console_scripts": [
            "secure-document=secure_document.cli:main",
        ],
    },
    author="Your Name",
    description="A secure document encryption tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
)
