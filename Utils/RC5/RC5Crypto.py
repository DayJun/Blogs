from RO import *

a5 = [
    0xa84cc30f, 0x8c542814, 0x707b11ca, 0x9e8dd4da, 0xb4245f97, 0x2d1b26a1,
    0x597f945, 0xb5f5fbf6, 0xa7995bcc, 0xeb581212, 0x9b2334df, 0x3084c61d,
    0xcb34a45f, 0x3c5b7065, 0xde5abc72, 0x401bb1de, 0x3db93985, 0x2f2fdf55,
    0x3bea76b1, 0x934ef08, 0xf311184d, 0x4eb65563, 0x724090ca, 0xedd9079e,
    0xd1519c43, 0x4b435966, 0x6d26d46f, 0xa487e963, 0x7bed4d8e, 0x2178b132,
    0x8a7832fc, 0xc41d1d33, 0x76d72b95, 0xae07ecb, 0x18e2b2fa, 0x3d6e5a03,
    0x7f538a68, 0xdf84e49c, 0x4a1c22a7, 0x915534e6, 0xc1bb4315, 0xd7867111,
    0x92823dbf, 0x514d895a
]


def decode(a1, a2, a3, a4, a5):
    a3 -= a5[43]
    a1 -= a5[42]
    for i in range(2, 42, 2):
        v9 = a4
        a4 = a3
        a3 = a2
        a2 = a1
        a1 = v9
        v6 = ROR(((2 * a2 + 1) * a2) & 0xffffffff, 5, 32)
        v7 = ROR(((2 * a4 + 1) * a4), 5, 64)
        v8 = v7 >> 31 >> 27
        a1 = ROR((a1 - a5[i]) & 0xffffffff, (v7&0xffffffff + v8) & 0x1f - v8, 32) ^ v6
        a3 = ROR((a3 - a5[i + 1]) & 0xffffffff, v6 % 32, 32) ^ v7&0xffffffff
    a2 = (a2 - a5[0]) & 0xffffffff
    a4 = (a4 - a5[1]) & 0xffffffff
    return (a1, a2, a3, a4)


a = 0x3596C80A
b = 0xFF99804C
c = 0x50DFF336
d = 0x253BD30
ans = decode(a, b, c, d, a5)
for i in ans:
    print(hex(i))
