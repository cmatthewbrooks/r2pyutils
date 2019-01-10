# r2pyutils
A repository of r2pipe-related Python utilities meant to be included as a git submodule within other script repositories.

+ r2ppipeutil.py - A wrapper utility for r2pipe
+ r2pfuncutil.py - A utility to work with 'func' objects from r2
+ funclist.py - An example utility script to find 'first round' and 'utility' functions during an r2
session
+ funcstrings.py - An example utility script to print out all strings referenced within functions
during an r2 session

Note: Python 2 and 3 are both supported.

# Installation

```bash
git clone https://github.com/cmatthewbrooks/r2pyutils.git
cd r2pyutils
pip install .
```

# TODO
+ Add usage examples to README
+ Add this repository to the [r2 package manager](https://github.com/radare/radare2-pm)
