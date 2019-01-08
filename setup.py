from setuptools import setup

setup(

    name = 'r2pyutils',
    version = '0.1',
    author = 'cmatthewbrooks',
    author_email = 'me@cmatthewbrooks.com',
    keywords = ['radare2'],
    packages = ['r2pyutils'],
    entry_points = {
        'console_scripts': [
        'funcstrings = r2pyutils.funcstrings:main'
        ]
    },
    install_requires = [
        'r2pipe'
    ]

)
