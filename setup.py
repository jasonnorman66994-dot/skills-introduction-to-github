"""Setup configuration for zero-trust package distribution."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="zero-trust",
    version="0.1.0",
    author="Zero Trust Dev",
    author_email="dev@skills-lab.local",
    description="A comprehensive zero trust security framework with MFA and least privilege authorization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jasonnorman66994-dot/skills-introduction-to-github",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.10",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "black>=26.3.1",
            "flake8>=6.1.0",
            "mypy>=1.7.1",
        ],
        "api": [
            "fastapi>=0.109.1",
            "uvicorn>=0.27.0",
            "pydantic>=2.5.0",
        ],
        "docs": [
            "sphinx>=7.2.6",
            "sphinx-rtd-theme>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [],
    },
)
