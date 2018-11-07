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


#####################################################################
'''
    This section contains test functions to test the methods
    implemented above.
'''
#####################################################################

def test_get_analyzed_r2pipe_from_input():
    
    print("Testing get_analyzed_r2pipe_from_input():")

    print("\nTesting input_obj=None...")

    try:
        r2 = R2PipeUtility.get_analyzed_r2pipe_from_input()
    except Exception:
        print ("Testing input_obj=None...TEST PASSED.\n")

    print("\nTesting input_obj=R2PIPE_CLASS_NAME...")
    
    r2 = r2pipe.open("/bin/ls")
    r2 = R2PipeUtility.get_analyzed_r2pipe_from_input(r2)
    if int(r2.cmd('aflc')) == 0:
        print("Testing input_obj=R2PIPE_CLASS_NAME...TEST FAILED.\n")
    else:
        print("Analyzed func count is: ", str(r2.cmd('aflc')))
        print("Testing input_obj=R2PIPE_CLASS_NAME...TEST PASSED.\n")

    print("\nTesting input_obj=file...")

    r2 = None
    r2 = R2PipeUtility.get_analyzed_r2pipe_from_input("/bin/ls") 
    if int(r2.cmd('aflc')) == 0:
        print("Testing input_obj=file...TEST FAILED.\n")
    else:
        print("Analyzed func count is: ", str(r2.cmd('aflc')))
        print("Testing input_obj=file...TEST PASSED.\n")

if __name__ == '__main__':

    test_get_analyzed_r2pipe_from_input()
