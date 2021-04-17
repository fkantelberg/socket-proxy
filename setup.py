import os

from setuptools import find_packages, setup


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()


setup(
    name="socket-proxy",
    version="1.7",
    author="Florian Kantelberg",
    author_email="florian.kantelberg@mailbox.org",
    description="Proxy TCP ports of local systems",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    license="MIT",
    keywords="proxy socket network",
    url="https://github.com/fkantelberg/socket-proxy",
    packages=find_packages("src"),
    package_dir={"": "src"},
    include_package_data=True,
    entry_points={"console_scripts": ["socket_proxy = socket_proxy.main:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)
