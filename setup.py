import os

from setuptools import find_packages, setup


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()


setup(
    name="socket-proxy",
    version="0.1",
    author="...",
    author_email="...",
    description="...",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    license="MIT",
    keywords="proxy socket",
    url="...",
    packages=find_packages("src"),
    package_dir={"": "src"},
    include_package_data=True,
    entry_points={"console_scripts": ["socket_proxy = socket_proxy.main:main"]},
    python_requires=">=3.7",
)
