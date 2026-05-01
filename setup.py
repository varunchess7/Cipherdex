from setuptools import setup

setup(
    name="cipher-tool",
    version="0.1",
    py_modules=["main", "ciphers"],
    install_requires=["typer", "rich"],
    entry_points={
        'console_scripts': [
            'cryptic=main:app',
        ],
    },
)