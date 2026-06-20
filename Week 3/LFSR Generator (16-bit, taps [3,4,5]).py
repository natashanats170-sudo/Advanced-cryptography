def lfsr(seed, taps, n_bits):
    register = seed
    bits = []
    for _ in range(n_bits):
        feedback = 0
        for tap in taps:
            feedback ^= (register >> tap) & 1
        bits.append(register & 1)
        register = (register >> 1) | (feedback << 15)
    return bits

output = lfsr(0xACE1, [3, 4, 5], 50)
print(output)
