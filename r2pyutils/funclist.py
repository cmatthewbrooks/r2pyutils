import os,sys
import argparse

import r2pipe

from .r2ppipeutil import R2PipeUtility as r2pu
from .r2pfuncutil import R2FuncUtility as r2fu



class FuncList:

    LIST_TYPES = ['firstround','utility']

    def __init__(self, list_type, r2):
       
        if r2pu.is_valid_r2pipe_instance(r2):
            self.r2 = r2
        else:
            raise Exception('Not inside an r2 session.')

        if list_type in FuncList.LIST_TYPES:
            self.list_type = list_type
        else:
            raise Exception('Not a valid list type.')

        self.func_list = set()

        self.populate_list(self.list_type)

    def populate_list(self, list_type):

        if list_type == 'firstround':
            self.func_list.update(self.get_first_round_list())
        elif list_type == 'utility':
            self.func_list.update(self.get_utility_list())

    def get_first_round_list(self):

        first_round_funcs = []

        funcj_list = r2pu.get_funcj_list(self.r2)

        for funcj in funcj_list:

            if (funcj['name'].startswith('fcn.') and
                r2fu.check_is_first_round_func(funcj)):
                first_round_funcs.append(funcj['name'])

        return first_round_funcs

    def get_utility_list(self):

        utility_funcs = []

        funcj_list = r2pu.get_funcj_list(self.r2)

        for funcj in funcj_list:

            if (funcj['name'].startswith('fcn.') and
                r2fu.check_is_utility_func(funcj)):
                utility_funcs.append(funcj['name'])

        return utility_funcs

    def print_functions(self):

            for func in sorted(self.func_list):
                print(func)



def main():

    parser = argparse.ArgumentParser()

    list_type = parser.add_mutually_exclusive_group(required=True)

    list_type.add_argument('-u','--utility',action='store_true',
        help='Print the utility functions (used by 3 or more functions)')
    list_type.add_argument('-fr','--firstround',action='store_true',
        help='Print the first-round functions (no call instructions)')

    args = parser.parse_args()

    r2 = r2pu.get_analyzed_r2pipe_from_input()

    if args.utility:
        fl = FuncList('utility', r2)
    elif args.firstround:
        fl = FuncList('firstround', r2)
    else:
        raise Exception('\nCannot execute this list type.\n')

    fl.print_functions()



if __name__ == '__main__':
    main()
