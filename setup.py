import setuptools

setuptools.setup(
    name="transible",
    version="0.0.2",
    author="Sagi (Sergey) Shnaidman",
    author_email="einarum@gmail.com",
    description="Transible package",
    long_description="""Transible tool allows you to get
                        your cloud configuration and infrastructure
                        into Ansible plabyooks.""",
    long_description_content_type="text/markdown",
    url="https://github.com/sshnaidm/transible",
    project_urls={
        "Bug Tracker": "https://github.com/sshnaidm/transible/issues/",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache License",
        "Operating System :: OS Independent",
    ],
    entry_points={'console_scripts': ['transible = transible:main']},
    packages=setuptools.find_packages(),
    python_requires=">=3.7",
)
