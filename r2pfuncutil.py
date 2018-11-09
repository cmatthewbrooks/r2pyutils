'''
AUTHOR:

    Matt Brooks, @cmatthewbrooks

DESCRIPTION:

    This module is a class to assist with working
    with funcj objects returned from the 'pdfj'
    command or afij objects returned from the 'afji'
    command.

'''



import r2pipe



class R2FuncUtility:

    @staticmethod
    def check_is_import_jmp_func(funcj):

        if (len(funcj['ops']) == 1
            and funcj['size'] == 6
            and funcj['ops'][0]['type'] == 'jmp'):

            return True

        else:

            return False

