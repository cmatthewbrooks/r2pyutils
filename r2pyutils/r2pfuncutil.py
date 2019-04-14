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



IMPORT = 'import'
GLOBAL = 'global'
THUNK = 'thunk'
WRAPPER = 'wrapper'
FIRST_ROUND = 'firstround'
UTILITY = 'utility'
UNKNOWN = 'unknown'



def classify_func(self, funcj):

    if check_is_import_jmp_func(funcj):
        return IMPORT
    elif check_is_global_assignment_func(funcj):
        return GLOBAL
    elif check_is_thunk_func(funcj):
        return THUNK
    elif check_is_wrapper_func(funcj):
        return WRAPPER
    elif check_is_first_round_func(funcj):
        return FIRST_ROUND
    elif check_is_utility_func(funcj):
        return UTILITY
    else:
        return UNKNOWN


def check_is_analysis_func(funcj):

    if (check_is_import_jmp_func(funcj) or
        check_is_global_assignment_func(funcj) or
        check_is_thunk_func(funcj) or
        check_is_wrapper_func(funcj)):

        return False

    else:

        return True


def check_is_first_round_func(funcj):

    calls = get_call_count_from_funcj(funcj)

    if calls == 0:

        return True

    elif calls > 0:

        return False


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


def check_is_complex_func(afij):

    if afij['nbbs'] > 5:
        return True
    else:
        return False


def check_is_import_jmp_func(funcj):

    if (len(funcj['ops']) == 1
        and funcj['size'] == 6
        and funcj['ops'][0]['type'] == 'jmp'):

        return True

    else:

        return False


def check_is_global_assignment_func(funcj):

    if (funcj['ops'][0]['type'] == 'mov'
        and funcj['ops'][1]['type'] == 'ret'):

        return True

    else:

        return False


def check_is_wrapper_func(funcj):

    calls = get_call_count_from_funcj(funcj)

    if (len(funcj['ops']) > 3 and
        len(funcj['ops']) <= 20 and
        calls == 1):

        return True

    else:

        return False


def check_is_thunk_func(funcj):

    if 1 < len(funcj['ops']) <= 3:

        return True

    else:

        return False


def get_call_count_from_funcj(funcj):

    count = 0

    for op in funcj['ops']:

        if 'call' in op.get('opcode','N/A'):
            count += 1

    return count
