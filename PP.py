import hashlib
import base58
import ecdsa
import requests
import time

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    return hashlib.new('ripemd160', data).digest()

def to_wif(private_key_hex):
    extended_key = '80' + private_key_hex
    first_sha = sha256(bytes.fromhex(extended_key))
    second_sha = sha256(first_sha)
    checksum = second_sha[:4]
    wif_key = extended_key + checksum.hex()
    return base58.b58encode(bytes.fromhex(wif_key)).decode('utf-8')

def generate_keys_from_passphrase(passphrase):
    private_key_hex = hashlib.sha256(passphrase.encode('utf-8')).hexdigest()
    wif_key = to_wif(private_key_hex)
    
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()
    
    # Calcola l'hash della chiave pubblica per ottenere l'indirizzo P2PKH
    public_key_hash = ripemd160(sha256(public_key))
    p2pkh_prefix = b'\x00'  # Prefisso per P2PKH (Bitcoin Mainnet)
    address = p2pkh_prefix + public_key_hash
    checksum = sha256(sha256(address))[:4]
    bitcoin_address = base58.b58encode(address + checksum).decode('utf-8')

    return private_key_hex, wif_key, public_key.hex(), bitcoin_address

def check_address_balance(bitcoin_address):
    url = f"https://blockchain.info/rawaddr/{bitcoin_address}"
    try:
        response = requests.get(url)
        response_data = response.json()
        balance = response_data['final_balance']
        total_received = response_data['total_received']
        return balance, total_received
    except Exception as e:
        print("Error checking address:", e)
        return None, None

while True:
    print("")
    print("========= BITCOIN PASSPHRASE DECODER ============")
    print("")
    print("This Python program is designed to generate a")
    print("Bitcoin private key, public key (HEX) and (WIF), and a corresponding Bitcoin address (P2PKH)")
    print("from a user-provided passphrase")
    print("===============================================")
    print("")

    # Richiedi la passphrase dall'utente
    passphrase = input("Insert passphrase (with space) and hit Enter: ")

    # Genera tutte le chiavi
    private_key_hex, wif_key, public_key, bitcoin_address = generate_keys_from_passphrase(passphrase)

    # Output delle chiavi generate
    print("===============================================")
    print("")
    print("Passphrase:>>>", passphrase)
    print("")
    print("Private Key (HEX):>>>", private_key_hex)
    print("")
    print("Private Key (WIF):>>>", wif_key)
    print("")
    print("Public Key:>>>", public_key)
    print("")
    print("Bitcoin Address (P2PKH):>>>", bitcoin_address)
    print("")

    # Controlla il saldo dell'indirizzo Bitcoin
    balance, total_received = check_address_balance(bitcoin_address)
    if balance is not None:
        print(f"Address has a balance of: {balance / 1e8} BTC")
        print(f"Total received by address: {total_received / 1e8} BTC")
        print("")
        print("")
        print("")
    else:
        print("Could not retrieve balance information.")
        print("")
    
    print("===============================================")

    # Pausa per evitare che la finestra si chiuda immediatamente
    input("\n Hit Enter to try a new passphrase or CTRL+C to exit...")
    print("")
    print("")
