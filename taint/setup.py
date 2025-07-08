from setuptools import setup, find_packages

setup(
    name="j-sentinel",
    version="0.1.0",
    description="Java Security Analysis Tool with Taint Analysis",
    packages=find_packages(),
    install_requires=[
        "pydantic>=1.8.0",
        "networkx>=2.5",
        "PyYAML>=5.4.0",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "j-sentinel-taint=taint.main:main",
        ],
    },
)