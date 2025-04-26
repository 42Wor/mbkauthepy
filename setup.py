from setuptools import setup, find_packages

setup(
    name="mbkauthepy",  # Name of your package
    version="1.3.0",  # Current version
    author="Maaz.waheed",
    author_email="maaz.waheed@mbktechstudio.com",
    description="A fully featured, secure, and extensible authentication system for Python Flask applications.",
    long_description=open("README.md").read(),  # Read long description from README
    long_description_content_type="text/markdown",  # Assuming your README is markdown
    url="https://github.com/42Wor/mbkauthepy",  # URL to the project's homepage or repository
    packages=find_packages(where=".", include=["mbkauthepy"]),  # Auto-discover all packages
    package_data={  # Include non-Python files (e.g., templates)
        "mbkauthepy": ["templates/Error/*.html"],
    },
    classifiers=[  # Classifiers to categorize your package
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Topic :: Security",
        "Framework :: Flask",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Web Environment",
    ],
    install_requires=[  # List of dependencies
        "Flask>=2.0",
        "Flask-Session>=0.5",
        "psycopg2-binary>=2.9",
        "python-dotenv>=1.0",
        "bcrypt>=4.0",
        "requests>=2.28",
        "pyotp>=2.8",
        "Flask-Cors>=4.0",
        "SQLAlchemy>=1.4",
        "importlib-metadata; python_version<'3.10'",  # Dependency for Python versions below 3.10
    ],
    python_requires=">=3.8",  # Python version requirement
    license="MIT",  # License type (use SPDX identifier)
    keywords=["flask", "authentication", "session", "auth", "postgresql", "security"],
    include_package_data=True,  # Include package data specified in MANIFEST.in
    zip_safe=False,  # If your package can be reliably used from a .egg file
    entry_points={  # Optional entry points if you're creating command-line tools
        'console_scripts': [
            'mbkauthepy=mbkauthepy.__main__:main',  # Example command-line tool
        ],
    },
    license_files=["LICENSE"],  # Include the license file
)
