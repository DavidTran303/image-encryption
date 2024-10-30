from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Input and output file paths
input_image = "top_secret.bmp"
encrypted_image = "encrypted_image_ecb.bmp"
decrypted_image = "decrypted_image_ecb.bmp"

# AES Key and Cipher (ECB Mode) - ECB is not secure!
key = os.urandom(16)
aesCipherECB = Cipher(algorithms.AES(key),
                      modes.ECB(),
                      backend=default_backend())


#aesEncryptor and aesDecryptor objects here using the cipher
aesEncyptor = aesCipherECB.encryptor()
aesDecryptor = aesCipherECB.decryptor()

# Function to encrypt an image file in ECB mode
# Function to encrypt an image file in ECB mode
def encrypt_image_ecb(ifile, ofile):
    with open(ifile, "rb") as reader:
        with open(ofile, "wb+") as writer:
            image_data = reader.read()
            header, body = image_data[:54], image_data[54:]  # Fix: swapped header and body
            padding_length = 16 - len(body) % 16  # Corrected padding for body
            body += b"\x00" * padding_length  # Fix: Ensure padding is in bytes
            encrypted_body = aesEncyptor.update(body) + aesEncyptor.finalize()  # Fix: finalize encryption
            writer.write(header + encrypted_body)  # Write header + encrypted body
    return

#Write the header and decrypt the body image
# Function to decrypt an image file that was encrypted in ECB mode
def decrypt_image_ecb(ifile, ofile):
    with open(ifile, "rb") as reader:
        with open(ofile, "wb+") as writer:
            image_data = reader.read()
            header, body = image_data[:54], image_data[54:]
            decrypted_body = aesDecryptor.update(body) + aesDecryptor.finalize()  # Decrypt the body

            # Remove padding (assuming padding used is null bytes)
            decrypted_body = decrypted_body.rstrip(b"\x00")

            writer.write(header + decrypted_body)
    return


if __name__ == '__main__':
    #Call the function to encrypt the image and provide input/output file paths
    encrypt_image_ecb(input_image, encrypted_image)
    #Calls the function to decrypt the image and provide input/output file paths
    decrypt_image_ecb(encrypted_image, decrypted_image)
    #Print confirmation messages when encryption and decryption are done
    print("Done")
    # In ECB (Electronic Codebook) mode, each block of plaintext is encrypted independently. This means identical plaintext blocks are encrypted into identical ciphertext blocks.
    # The lack of diffusion reveals patterns in the encrypted data, which is evident when encrypting an image.
    # Since repeating patterns in the plaintext (such as colors or textures in an image) are not masked,
    # the structure of the original image can still be discerned in the encrypted version, showing why ECB mode is insecure.
    exit(1)
