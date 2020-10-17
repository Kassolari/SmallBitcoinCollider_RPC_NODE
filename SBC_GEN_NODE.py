import os, binascii, hashlib, base58, ecdsa
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException


def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

balance = 0
n = 0
rpc_user = "user1"
rpc_password = "password1"

while balance == 0:  # if balance is something :)

    # generate private key , uncompressed WIF starts with "5"
    priv_key = os.urandom(32)
    fullkey = '80' + binascii.hexlify(priv_key).decode()
    sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
    sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
    WIF = base58.b58encode(binascii.unhexlify(fullkey + sha256b[:8]))

    # get public key , uncompressed address starts with "1"
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
    hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
    publ_addr_a = b"\x00" + hash160
    checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
    publ_addr_b = base58.b58encode(publ_addr_a + checksum)

    # rpc_user and rpc_password are set in the bitcoin.conf file
    rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%(rpc_user, rpc_password))
    #wallet_balance = rpc_connection.getreceivedbylabel(publ_addr_b.decode())
    
    print(n)
    n+=1
    print("Private Key : " + WIF.decode())
    print("Bitcoin Address: " + publ_addr_b.decode())
    #print("Balance: " +  str(float(wallet_balance)))
    
    if rpc_connection.getreceivedbylabel(publ_addr_b.decode()) != 0:
       print("Znaleziono:")
       print("Private Key : " + WIF.decode())
       print("Bitcoin Address: " + publ_addr_b.decode())
       print("Balance: " +  str(float(wallet_balance)))
       balance = 1
       break
