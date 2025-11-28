#!/usr/bin/env python3
"""
AI Pentest Tool - Setup
An AI-assisted penetration testing tool with Cursor API integration
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ai-pentest",
    version="1.0.0",
    author="AI Pentest Team",
    author_email="security@example.com",
    description="AI-assisted penetration testing tool with Cursor API integration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/ai-pentest",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ai-pentest=ai_pentest.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ai_pentest": [
            "reports/templates/*.html",
            "reports/templates/*.css",
        ],
    },
)
