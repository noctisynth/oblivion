from oblivion import __version__

import setuptools

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name = "oblivion",
    version = __version__,
    author = "Night Resurgent <fu050409@163.com>",
    author_email = "fu050409@163.com",
    description = "Cipher",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "Cipher",
    project_urls = {
        "Bug Tracker": "Cipher",
    },
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    license = "Apache-2.0",
    packages = setuptools.find_packages(),
    install_requires = [
        'pycryptodome'
    ],
    python_requires=">=3",
)
