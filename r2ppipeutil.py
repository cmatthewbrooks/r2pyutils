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
    def get_analyzed_r2pipe_from_input(input_obj = None):

        if not input_obj:
            r2 = r2pipe.open()
        elif str(input_obj.__class__) == R2PipeUtility.R2PIPE_CLASS_NAME:
            r2 = input_obj
        elif os.path.isfile(str(input_obj)):
            r2 = r2pipe.open(input_obj)
        else:
            raise Exception('Error: Not inside an r2 session.')

        try:
            r2.cmd("aflc")
        except IOError:
            raise Exception('Error: Not inside an r2 session.')


        if int(r2.cmd('aflc')) == 0:
            # If there are no functions, analyze the file
            r2.cmd("aa; aar; aac")


        return r2

