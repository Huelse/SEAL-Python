from seal import scheme_type


def print_example_banner(title):
    title_length = len(title)
    banner_length = title_length + 2 * 10
    banner_top = '+' + '-' * (banner_length - 2) + '+'
    banner_middle = '|' + ' ' * 9 + title + ' ' * 9 + '|'
    print(banner_top)
    print(banner_middle)
    print(banner_top)


def print_parameters(context):
    context_data = context.key_context_data()
    if context_data.parms().scheme() == scheme_type.bfv:
        scheme_name = 'bfv'
    elif context_data.parms().scheme() == scheme_type.ckks:
        scheme_name = 'ckks'
    else:
        scheme_name = 'none'
    print('/')
    print('| Encryption parameters')
    print('| scheme: ' + scheme_name)
    print(f'| poly_modulus_degree: {context_data.parms().poly_modulus_degree()}')
    coeff_modulus = context_data.parms().coeff_modulus()
    coeff_modulus_sum = 0
    for j in coeff_modulus:
        coeff_modulus_sum += j.bit_count()
    print(f'| coeff_modulus size: {coeff_modulus_sum}(', end='')
    for i in range(len(coeff_modulus) - 1):
        print(f'{coeff_modulus[i].bit_count()} + ', end='')
    print(f'{coeff_modulus[-1].bit_count()}) bits')
    if context_data.parms().scheme() == scheme_type.bfv:
        print(f'| plain_modulus: {context_data.parms().plain_modulus().value()}')
    print('\\')


def print_vector(vec, print_size=4, prec=3):
    slot_count = len(vec)
    print()
    if slot_count <= 2*print_size:
        print('    [', end='')
        for i in range(slot_count):
            print(f' {vec[i]:.{prec}f}' + (',' if (i != slot_count - 1) else ' ]\n'), end='')
    else:
        print('    [', end='')
        for i in range(print_size):
            print(f' {vec[i]:.{prec}f},', end='')
        if slot_count > 2*print_size:
            print(' ...,', end='')
        for i in range(slot_count - print_size, slot_count):
            print(f' {vec[i]:.{prec}f}' + (',' if (i != slot_count - 1) else ' ]\n'), end='')
    print()
