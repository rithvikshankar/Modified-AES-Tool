sBox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

invSBox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


def subBytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = sBox[s[i][j]]


def invSubBytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = invSBox[s[i][j]]


def shiftRows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def invShiftRows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def addRoundKey(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


def to8bitBinary(a):
    bnr = bin(a)[2:]
    bnr = '0'*(8 - len(bnr)) + bnr
    return bnr

# def permutate(arrs):
#     perm = [['0','0','0','0'],['0','0','0','0'],['0','0','0','0'],['0','0','0','0']]
#     for x in range(4):
#         for i in range(4):
#             perm[i][x] = to8bitBinary(arrs[i][x])
#
#     arr = [[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0]]
#     for i in range(4):
#         for j in range(4):
#             arr[j][i] = perm[0][j][2*i] + perm[1][j][2*i] + perm[2][j][2*i] + perm[3][j][2*i] + perm[0][j][2*i+1] + perm[1][j][2*i+1] + perm[2][j][2*i+1] + perm[3][j][2*i+1]
#
#     newarr = [[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0]]
#     for i in range(4):
#         for j in range(4):
#             newarr[i][j] = binaryToDecimal(arr[i][j])
#     return newarr

def permutate(arrs):
    perm = [['0','0','0','0'],['0','0','0','0'],['0','0','0','0'],['0','0','0','0']]
    arr = [[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0]]
    newarr = [[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0]]
    for i in range(4):
        perm[0] = to8bitBinary(arrs[0][i])
        perm[1] = to8bitBinary(arrs[1][i])
        perm[2] = to8bitBinary(arrs[2][i])
        perm[3] = to8bitBinary(arrs[3][i])
        arr[i][0] = perm[0][0] + perm[1][0] + perm[2][0] + perm[3][0] + perm[0][1] + perm[1][1] + perm[2][1] + perm[3][1]
        arr[i][1] = perm[0][2] + perm[1][2] + perm[2][2] + perm[3][2] + perm[0][3] + perm[1][3] + perm[2][3] + perm[3][3]
        arr[i][2] = perm[0][4] + perm[1][4] + perm[2][4] + perm[3][4] + perm[0][5] + perm[1][5] + perm[2][5] + perm[3][5]
        arr[i][3] = perm[0][6] + perm[1][6] + perm[2][6] + perm[3][6] + perm[0][7] + perm[1][7] + perm[2][7] + perm[3][7]
        newarr[i][0] = int(arr[i][0],2)
        newarr[i][1] = int(arr[i][1],2)
        newarr[i][2] = int(arr[i][2],2)
        newarr[i][3] = int(arr[i][3],2)
    return newarr

# def binaryToDecimal(n):
#     return int(n,2)

def inpermutate(arrs):
    arr = [[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0]]
    newarr = [[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0],[0, 0, 0, 0]]
    perm = ['','','','']
    for i in range(4):
        perm[i] = perm[i] + to8bitBinary(arrs[i][0])
        perm[i] = perm[i] + to8bitBinary(arrs[i][1])
        perm[i] = perm[i] + to8bitBinary(arrs[i][2])
        perm[i] = perm[i] + to8bitBinary(arrs[i][3])

        arr[0][i] = perm[i][0] + perm[i][4] + perm[i][8] + perm[i][12] + perm[i][16] + perm[i][20] + perm[i][24] + perm[i][28]
        arr[1][i] = perm[i][1] + perm[i][5] + perm[i][9] + perm[i][13] + perm[i][17] + perm[i][21] + perm[i][25] + perm[i][29]
        arr[2][i] = perm[i][2] + perm[i][6] + perm[i][10] + perm[i][14] + perm[i][18] + perm[i][22] + perm[i][26] + perm[i][30]
        arr[3][i] = perm[i][3] + perm[i][7] + perm[i][11] + perm[i][15] + perm[i][19] + perm[i][23] + perm[i][27] + perm[i][31]

        newarr[0][i] = int(arr[0][i],2)
        newarr[1][i] = int(arr[1][i],2)
        newarr[2][i] = int(arr[2][i],2)
        newarr[3][i] = int(arr[3][i],2)
    return newarr


rCon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytesToMatrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrixToBytes(matrix):
    return bytes(sum(matrix, []))

def xorBytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def incBytes(a):
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

def pad(pt):
    paddingLength = 16 - (len(pt) % 16)
    padding = bytes([paddingLength] * paddingLength)
    return pt + padding

def unpad(pt):
    paddingLength = pt[-1]
    assert paddingLength > 0
    msg, padding = pt[:-paddingLength], pt[-paddingLength:]
    assert all(p == paddingLength for p in padding)
    return msg

def splitBlocks(msg, blockSize=16, requirePadding=True):
        assert len(msg) % blockSize == 0 or not requirePadding
        return [msg[i:i+16] for i in range(0, len(msg), blockSize)]


class AES:
    roundsToKeySize = {16: 10, 24: 12, 32: 14}

    def __init__(self, masterKey):
        assert len(masterKey) in AES.roundsToKeySize
        self.nRounds = AES.roundsToKeySize[len(masterKey)]
        self._keyMatrices = self._expandKey(masterKey)

    def _expandKey(self, masterKey):
        keyColumns = bytesToMatrix(masterKey)
        iterationSize = len(masterKey) // 4

        i = 1
        while len(keyColumns) < (self.nRounds + 1) * 4:
            word = list(keyColumns[-1])

            if len(keyColumns) % iterationSize == 0:
                word.append(word.pop(0))
                word = [sBox[b] for b in word]
                word[0] ^= rCon[i]
                i += 1
            elif len(masterKey) == 32 and len(keyColumns) % iterationSize == 4:
                word = [sBox[b] for b in word]

            word = xorBytes(word, keyColumns[-iterationSize])
            keyColumns.append(word)

        return [keyColumns[4*i : 4*(i+1)] for i in range(len(keyColumns) // 4)]

    def encryptBlock(self, pt):
        assert len(pt) == 16

        plainState = bytesToMatrix(pt)

        addRoundKey(plainState, self._keyMatrices[0])

        for i in range(1, self.nRounds):
            subBytes(plainState)
            shiftRows(plainState)
            plainState = permutate(plainState)
            addRoundKey(plainState, self._keyMatrices[i])

        subBytes(plainState)
        shiftRows(plainState)
        addRoundKey(plainState, self._keyMatrices[-1])

        return matrixToBytes(plainState)

    def decryptBlock(self, ct):
        assert len(ct) == 16

        cipherState = bytesToMatrix(ct)

        addRoundKey(cipherState, self._keyMatrices[-1])
        invShiftRows(cipherState)
        invSubBytes(cipherState)

        for i in range(self.nRounds - 1, 0, -1):
            addRoundKey(cipherState, self._keyMatrices[i])
            cipherState = inpermutate(cipherState)
            invShiftRows(cipherState)
            invSubBytes(cipherState)

        addRoundKey(cipherState, self._keyMatrices[0])

        return matrixToBytes(cipherState)

    def encryptCBC(self, pt, iv):
        assert len(iv) == 16

        pt = pad(pt)

        blocks = []
        previous = iv
        for ptextBlock in splitBlocks(pt):
            block = self.encryptBlock(xorBytes(ptextBlock, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decryptCBC(self, ct, iv):

        assert len(iv) == 16

        blocks = []
        previous = iv
        for ctextBlock in splitBlocks(ct):
            blocks.append(xorBytes(previous, self.decryptBlock(ctextBlock)))
            previous = ctextBlock

        return unpad(b''.join(blocks))

import os
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest

aesKeySize = 16
hmacKeySize = 16
ivSize = 16

saltSize = 16
hmacSize = 32

def getKeyIV(password, salt, workload=100000):
    stretch = pbkdf2_hmac('sha256', password, salt, workload, aesKeySize + ivSize + hmacKeySize)
    aesKey, stretch = stretch[:aesKeySize], stretch[aesKeySize:]
    hmacKey, stretch = stretch[:hmacKeySize], stretch[hmacKeySize:]
    iv = stretch[:ivSize]
    return aesKey, hmacKey, iv


def encrypt(key, pt, workload=100000):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(pt, str):
        pt = pt.encode('utf-8')

    salt = os.urandom(saltSize)
    key, hmacKey, iv = getKeyIV(key, salt, workload)
    ct = AES(key).encryptCBC(pt, iv)
    hmac = new_hmac(hmacKey, salt + ct, 'sha256').digest()
    assert len(hmac) == hmacSize
    return hmac + salt + ct


def decrypt(key, ct, workload=100000):

    assert len(ct) % 16 == 0, "Cipher text must have 16 byte blocks."

    assert len(ct) >= 32, "Cipher text should be minimum 32 bytes"

    if isinstance(key, str):
        key = key.encode('utf-8')

    hmac, ct = ct[:hmacSize], ct[hmacSize:]
    salt, ct = ct[:saltSize], ct[saltSize:]
    key, hmacKey, iv = getKeyIV(key, salt, workload)

    hmacExpected = new_hmac(hmacKey, salt + ct, 'sha256').digest()
    assert compare_digest(hmac, hmacExpected), 'Cipher text is corrupted!'

    return AES(key).decryptCBC(ct, iv)


__all__ = [encrypt, decrypt, AES]

if __name__ == '__main__':
    import sys
    import base64
    import time
    import smtplib
    import getpass
    from email.message import EmailMessage
    import socket
    socket.setdefaulttimeout(100)


    print("\n1. Encrypt and mail file\n2. Decrypt file")
    ch = int(input("Enter choice: "))

    if ch == 1:
        print("\n1. Text file\n2. Image file")
        ch1 = int(input("Enter choice: "))

        if ch1 == 1:
            filename = input("\nEnter the file name: ")
            f = open(filename,"r")
            convertedString = f.read()

            key = "1234567890123456"

            if (len(key) != 16):
                print("Key size must be 16 characters long")

            else:
                c = encrypt(key,convertedString)

                f1 = open("tencrypted.txt","wb+")
                f1.write(c)
                f1.close()

                print("Encrypted file is saved as: tencrypted.txt")

            f.close()


        elif ch1 == 2:
            filename = input("\nEnter the file name: ")
            with open(filename, "rb") as image2string:
                convertedString = base64.b64encode(image2string.read())

            key = "1234567890123456" #input("Enter the key: ")

            if (len(key) != 16):
                print("Key size must be 16 characters long")
            else:

                c = encrypt(key,convertedString)

                f1 = open("iencrypted.txt","wb+")
                f1.write(c)
                f1.close()
                print("Encrypted file is saved as: iencrypted.txt")

        else:
            print("Invalid choice")
            exit()

        SenderEmail = "testingkumar999@gmail.com"
        ReceiverEmail = input('\nEmail: ')
        Password = "TestingKumar999"

        if ch1 == 1:
            fileName = 'tencrypted.txt'
        elif ch1 == 2:
            fileName = 'iencrypted.txt'
        else:
            exit()

        emessage = EmailMessage()
        emessage["From"] = SenderEmail
        emessage["Subject"] = "Encrypted file"
        emessage["To"] = ReceiverEmail

        emessage.set_content("Please find attached the encrypted file")
        emessage.add_attachment(open(fileName, "rb").read(), maintype = 'text', subtype = 'txt', filename = fileName)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(SenderEmail, Password)
            s.send_message(emessage)
        print("Mail sent successfully!")

    elif ch == 2:
        filename = input("\nEnter the file name: ")
        f = open(filename, "rb")
        c = f.read()

        if filename[0] == 't':
            key = "1234567890123456"

            if (len(key) != 16):
                print("Key size must be 16 characters long")
            else:

                d = decrypt(key,c)

                f1 = open("output.txt","w+")
                f1.write(d.decode('utf-8'))
                f1.close()

                print("Decrypted file is saved as: output.txt")

            f.close()

        elif filename[0] == 'i':
            key = "1234567890123456"

            if (len(key) != 16):
                print("Key size must be 16 characters long")
            else:

                d = decrypt(key,c)

                decoded = open('output.jpeg', 'wb')
                decoded.write(base64.b64decode(d.decode('utf-8')))
                decoded.close()

                print("Decrypted file is saved as: output.jpeg")


    else:
        print("Invalid choice")
