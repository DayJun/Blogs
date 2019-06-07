def ROL(int_value, k, bit=8):
    bit_strig = '{:0%db}' % bit
    bit_value = bit_strig.format(int_value)
    bit_value = bit_value[k:] + bit_value[:k]
    int_value = int(bit_value, 2)
    return int_value


def ROR(int_value, k, bit=8):
    bit_strig = '{:0%db}' % bit
    bit_value = bit_strig.format(int_value)
    bit_value = bit_value[-k:] + bit_value[:-k]
    int_value = int(bit_value, 2)
    return int_value
