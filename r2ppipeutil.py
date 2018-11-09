'''
AUTHOR:

    Matt Brooks, @cmatthewbrooks

DESCRIPTION:

    This module is a class to assist with working
    directly with an r2pipe instance. Anything using
    r2.cmd or r2.cmdj should be wrapped in this class
    ensuring an analyzed pipe.

'''

import os
import json
import r2pipe



class R2PipeUtility:
    ''' 
    Methods in this class are designed to work directly on a r2pipe
    object.
    '''

    R2PIPE_CLASS_NAME = 'r2pipe.open'

    @staticmethod
    def is_valid_r2pipe_instance(r2):
        
        if ("{0}.{1}".format(r2.__class__.__module__,
                             r2.__class__.__name__)
                             == R2PipeUtility.R2PIPE_CLASS_NAME):

            return True

        else:

            return False

    @staticmethod
    def get_analyzed_r2pipe_from_input(input_obj = None):

        if not input_obj:
            r2 = r2pipe.open()
        elif R2PipeUtility.is_valid_r2pipe_instance(input_obj):
            r2 = input_obj
        elif os.path.isfile(str(input_obj)):
            r2 = r2pipe.open(input_obj)
        else:
            raise Exception('Error: Not a valid r2pipe instance.')

        try:
            r2.cmd("aflc")
        except IOError:
            raise Exception('Error: Not a valid r2pipe instance.')


        if int(r2.cmd('aflc')) == 0:
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac; afta")

        return r2

    @staticmethod
    def get_funcj_list(r2):

        if not R2PipeUtility.is_valid_r2pipe_instance(r2):
            raise Exception('Error: Not a valid r2pipe instance.')

        funcj_list = []

        functions = r2.cmdj("aflj")

        if functions:

            for func in functions:

                funcj = r2.cmdj("pdfj @ " + hex(func['offset']))

                if funcj:

                    funcj_list.append(funcj)

        return funcj_list

    @staticmethod
    def get_function_start_from_offset(r2, offset=None):

        if not R2PipeUtility.is_valid_r2pipe_instance(r2):
            raise Exception('Error: Not a valid r2pipe instance.')
        
        if offset:
            return r2.cmdj('afij @ ' + hex(offset))[0]['offset']
        else:
            return r2.cmdj('afij')[0]['offset']



    @staticmethod
    def get_args_count_to_function_offset(r2, offset=None):

        if not R2PipeUtility.is_valid_r2pipe_instance(r2):
            raise Exception('Error: Not a valid r2pipe instance.')

        if offset:
            return r2.cmdj('afij @ ' + hex(offset))[0]['nargs']
        else:
            return r2.cmdj('afij')[0]['nargs']

