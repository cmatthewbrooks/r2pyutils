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

    R2PIPE_CLASS_NAME = 'r2pipe.open_sync.open'

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
            raise Exception(
                'Not a valid r2pipe instance or not inside an r2 session.'
            )

        try:
            r2.cmd('aflc')
        except AttributeError, e:
            if '\'open\' object has no attribute \'_cmd\'' in e:
                raise Exception(
                    'Not a valid r2pipe instance or not inside an r2 session.'
                )
        else:
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

    @staticmethod
    def get_call_xref_list_to_function_offset(r2, offset=None):

        if not R2PipeUtility.is_valid_r2pipe_instance(r2):
            raise Exception('Error: Not a valid r2pipe instance.')

        xref_list = []

        if offset:
            funcj = r2.cmdj('pdfj @ ' + hex(offset))
        else:
            funcj = r2.cmdj('pdfj')

        # The [0] hack is because xrefs to the function will
        # only be included in the first ops entry.
        if 'xrefs' in funcj['ops'][0]:
            for xref in funcj['ops'][0]['xrefs']:
                if xref['type'] == 'CALL':
                    xref_list.append(xref['addr'])

        return xref_list

