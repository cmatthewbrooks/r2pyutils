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


    IMPORT = 'import'
    GLOBAL = 'global'
    THUNK = 'thunk'
    WRAPPER = 'wrapper'
    FIRST_ROUND = 'firstround'
    UTILITY = 'utility'
    UNKNOWN = 'unknown'


    @staticmethod
    def classify_func(self, funcj):

        if R2FuncUtility.check_is_import_jmp_func(funcj):
            return R2FuncUtility.IMPORT
        elif R2FuncUtility.check_is_global_assignment_func(funcj):
            return R2FuncUtility.GLOBAL
        elif R2FuncUtility.check_is_thunk_func(funcj):
            return R2FuncUtility.THUNK
        elif R2FuncUtility.check_is_wrapper_func(funcj):
            return R2FuncUtility.WRAPPER
        elif R2FuncUtility.check_is_first_round_func(funcj):
            return R2FuncUtility.FIRST_ROUND
        elif R2FuncUtility.check_is_utility_func(funcj):
            return R2FuncUtility.UTILITY
        else:
            return R2FuncUtility.UNKNOWN

    @staticmethod
    def check_is_analysis_func(funcj):

        if (R2FuncUtility.check_is_import_jmp_func(funcj) or
            R2FuncUtility.check_is_global_assignment_func(funcj) or
            R2FuncUtility.check_is_thunk_func(funcj) or
            R2FuncUtility.check_is_wrapper_func(funcj)):

            return False

        else:

            return True

    @staticmethod
    def check_is_first_round_func(funcj):

        calls = R2FuncUtility.get_call_count_from_funcj(funcj)

        if calls == 0:

            return True

        elif calls > 0:

            return False

    @staticmethod
    def check_is_utility_func(funcj):

        call_xref_count = 0

        if 'xrefs' in funcj['ops'][0]:
            for xref in funcj['ops'][0]['xrefs']:
                if xref['type'] == 'CALL':
                    call_xref_count += 1

        if call_xref_count >= 3:
            return True
        elif call_xref_count <= 2:
            return False

    @staticmethod
    def check_is_complex_func(afij):

        if afij['nbbs'] > 5:
            return True
        else:
            return False

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
    def check_is_thunk_func(funcj):

        if 1 < len(funcj['ops']) <= 3:

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

    @staticmethod
    def get_import_from_import_jmp_func(funcj):

        op = funcj['ops'][0]

        return R2ParserUtility.parse_import_from_import_jmp_disasm(op)

    # The get_call_from_wrapper method needs better thought and
    # design. It's hacky right now.

    @staticmethod
    def get_call_from_wrapper(funcj):

        wrapper_call = ''

        for op in funcj['ops']:
            if 'call' in op.get('disasm','N/A'):
                wrapper_call = op.get('disasm','N/A')

        return wrapper_call

    @staticmethod
    def get_raw_call_chain_from_funcj(funcj):

        call_chain = []

        for op in funcj['ops']:
            if op['type'] in ['call','ucall']:
                call_chain.append(op['disasm'])

        return call_chain

    @staticmethod
    def get_func_stats_list_from_afij(afij):
        pass

