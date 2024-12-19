from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generar claves
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Cifrar mensaje
message = "Hola, este es un mensaje cifrado.".encode('utf-8')
cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_message = cipher.encrypt(message)

# Descifrar mensaje
decipher = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted_message = decipher.decrypt(encrypted_message)

print("Mensaje original:", message.decode())
print("Mensaje cifrado:", encrypted_message)
print("Mensaje descifrado:", decrypted_message.decode())
