from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="node-doctor",
    version="0.1.0-dev",
    author="Articulated7",  # Update this
    author_email="will@update.later",  # Update this
    description="A security and configuration auditing tool for Tor relay operators",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/node-doctor",  # Update this
    packages=find_packages(),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "colorama>=0.4.0",
    ],
    entry_points={
        "console_scripts": [
            "node-doctor=node_doctor.cli:main",
        ],
    },
)
