"""
Smart Contract Audit Tool - Setup
"""

from setuptools import setup, find_packages

setup(
    name="smart-audit",
    version="0.1.0",
    author="Security Audit Tool",
    description="Automated smart contract security audit platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "pydantic>=2.5.0",
        "gitpython>=3.1.0",
        "solcx>=0.2.0",
        "web3>=6.0.0",
        "jinja2>=3.1.0",
        "markdown>=3.5.0",
        "python-dotenv>=1.0.0",
        "aiofiles>=23.2.0",
        "httpx>=0.25.0",
    ],
    entry_points={
        "console_scripts": [
            "smart-audit=smart_audit.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
)
