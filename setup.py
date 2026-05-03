from setuptools import setup

setup(
    name="cipherdex",
    version="0.1.0",
    packages=["cipherdex"],
    install_requires=["typer", "rich"],
    entry_points={
        'console_scripts': [
            'cipherdex=cipherdex.main:app',
        ],
    },
)
