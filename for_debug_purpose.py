import des_encrypt_decrypt

file = open('data.txt','r')
data = file.read()
file.close()
k = des_encrypt_decrypt.des("DESCRYPT",             \
                            des_encrypt_decrypt.code_block_chain ,\
                            "\0\0\0\0\0\0\0\0",     \
                            pad=None, padmode=des_encrypt_decrypt.PKCS5_P)

d = k.encrypt(data)
print "Encrypted: %r" % d
print "Decrypted: %r" % k.decrypt(d)
#assert k.decrypt(d) == data
