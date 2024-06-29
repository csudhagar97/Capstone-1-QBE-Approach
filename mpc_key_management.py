import sys
from mpyc.runtime import mpc

# Initialize the MPyC runtime
mpc.run(mpc.start())

async def reconstruct_key_with_mpc(shares):
    # Ensure shares are in bytes and convert to integer representation for MPC
    secure_shares = [mpc.input(mpc.SecFld(256)(int.from_bytes(share.encode('utf-8'), 'big'))) for share in shares]
    secure_shares = await mpc.gather(secure_shares)

    # Combine the shares to reconstruct the key
    combined_key_int = sum(share.value for share in secure_shares) % (1 << 256)
    combined_key = combined_key_int.to_bytes((combined_key_int.bit_length() + 7) // 8, 'big')
    await mpc.shutdown()
    return combined_key.decode('utf-8')

if __name__ == "__main__":
    shares = sys.argv[1:]
    reconstructed_key = mpc.run(reconstruct_key_with_mpc(shares))
    print(reconstructed_key)
