#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

struct FileHeader
{
    uint32_t signature;
    byte unknown1[8];
    uint32_t encryptedsize;
    byte unknown2[8];
};

int main(int argc, char* argv[])
{
    FILE* stream;
    struct FileHeader fileheader;

    if (argc < 2) 
    {
        printf("CMvarDecrypt.exe <Path to Variables.dat file>\r\n");
        printf("CMvarDecrypt.exe <Path to Variables.dat file> <custom password>\r\n");
        exit(0);
    }

    if (fopen_s(&stream, argv[1], "rb") == 0)
    {
        
        if (fread(&fileheader, sizeof(fileheader), 1, stream) != 1) {
            fprintf(stderr, "Failed to read header\n");
            exit(-1);
        }
        
        // Crypt stuff
        HCRYPTPROV hCryptProv;
        DWORD dwStatus = 0;

        // PROV_RSA_AES = 0x18
        // CRYPT_VERIFYCONTEXT = F0000000
        if (!CryptAcquireContextW(&hCryptProv, 0, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            dwStatus = GetLastError();
            printf("CryptAcquireContext failed: %x\n", dwStatus);
            CryptReleaseContext(hCryptProv, 0);
            system("pause");
            return dwStatus;
        }

        HCRYPTHASH hHash;
        // CALG_SHA1 = 8004
        if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) {
            dwStatus = GetLastError();
            printf("CryptCreateHash failed: %x\n", dwStatus);
            CryptReleaseContext(hCryptProv, 0);
            system("pause");
            return dwStatus;
        }

        // Default encryption key SCCM
        wchar_t static_key[] = L"{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}";

        wchar_t* key = (wchar_t*)malloc(sizeof(wchar_t));


        if (argc == 3)
        {
            printf("Using custom password/key.\r\n");
            size_t argsize = strlen(argv[2]) + 1;
            size_t outSize;
            mbstowcs_s(&outSize, key, argsize, argv[2], argsize-1);
        }
        else 
        {
            
            key = static_key;
        }

        const size_t len = lstrlenW(key);
        const size_t key_size = len * sizeof(key[0]);

        if (!CryptHashData(hHash, (BYTE*)key, key_size, 0)) {
            DWORD err = GetLastError();
            printf("CryptHashData Failed : %#x\n", err);
            system("pause");
            return (-1);
        }

        //CALG_AES_128 = 0x0000660e
        HCRYPTKEY hKey;
        if (!CryptDeriveKey(hCryptProv, CALG_AES_128, hHash, 0, &hKey)) {
            dwStatus = GetLastError();
            printf("CryptDeriveKey failed: %x\n", dwStatus);
            CryptReleaseContext(hCryptProv, 0);
            system("pause");
            return dwStatus;
        }

        // Alloc buffer for encrypted bytes
        PBYTE buffer = NULL;
        if (!(buffer = (PBYTE)malloc(fileheader.encryptedsize)))
        {
            printf("Out of memory!\n");
            exit(-1);
        }

        // Read encrypted bytes into buffer
        if (fread(buffer, fileheader.encryptedsize, 1, stream) != 1) {
            fprintf(stderr, "Failed to read data\n");
            exit(-1);
        }

        // Decrypt
        DWORD size = (DWORD)fileheader.encryptedsize;
        if (!CryptDecrypt(hKey, 0, true, 0, buffer, &size)) {
            printf("CryptDecrypt failed: %x\n", GetLastError());
            exit(-1);
        }
        
        //Print decrypted contents
        fwrite(buffer, size, 1, stdout);
        
        fclose(stream);

    } else
    {
        fprintf(stderr, "Unable to open file \"%s\"\n", argv[1]);
        exit(-1);
    }
}

