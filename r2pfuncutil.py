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

    @staticmethod
    def check_is_global_assignment_func(funcj):

        if (funcj['ops'][0]['type'] == 'mov'
            and funcj['ops'][1]['type'] == 'ret'):

            return True

        else:

            return False

    @staticmethod
    def check_is_wrapper_func(funcj):

        calls = R2FuncUtility.get_call_count_from_funcj(funcj)

        if (len(funcj['ops']) > 3 and
            len(funcj['ops']) <= 20 and
            calls == 1):

            return True

        else:

            return False

    @staticmethod
    def get_call_count_from_funcj(funcj):

        count = 0

        for op in funcj['ops']:

            if 'call' in op.get('opcode','N/A'):
                count += 1

        return count

