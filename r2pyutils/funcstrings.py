import os,sys
import argparse
import json, base64

import r2pipe

from .r2ppipeutil import R2PipeUtility as r2pu


def get_func_strings(r2):

    string_sets = {}

    # First, get the strings and for each string, make sure it is
    # ascii or wide.
    strings = r2.cmdj('izzj')


    if not strings:
        raise Exception('Error: izzj returned no strings.')


    for string in strings:
        
        if string['type'] == 'ascii' or string['type'] == 'utf8':

            # Next, get the cross references to the string.
            xrefto = r2.cmdj("axtj " + str(string['vaddr']))

            if xrefto:

                for xref in xrefto:

                    # If the xref comes from a function, either add it
                    # to the list or add a new dictionary item.
                    if ('fcn_name' in xref and
                        len(base64.b64decode(string['string'])) >= 8):

                        if xref['fcn_name'] in string_sets:

                            string_sets[xref['fcn_name']].append(
                                base64.b64decode(string['string'])
                            )

                        elif xref['fcn_name'] not in string_sets:

                            string_sets[xref['fcn_name']] = (
                                [base64.b64decode(string['string'])]
                            )

    return string_sets


def main():

    r2 = r2pu.get_analyzed_r2pipe_from_input()

    #print(json.dumps(get_func_strings(r2), indent=4))
    print(get_func_strings(r2))

    r2.quit()



if __name__ == '__main__':
    main()
