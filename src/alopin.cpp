#include <cstdio>
#include <cstdint>
#include <thread>
#include <chrono>
#include <ctype.h>
#include <stdint.h>
#include <steam/steam_api.h>

extern "C" {
#include "proto/proto.h"
#include "crypto/scrypt.h"
#include "crypto/pbkdf2.h"
}

#define SALT_LEN 16
#define HASH_LEN 64

typedef struct{
    unsigned char* salt;
    size_t salt_size;
    unsigned char* hash;
    size_t hash_size;
    int hashtype;
} ALOPIN_CTX;


bool brute_pin(ALOPIN_CTX* ctx){
    for(char a = '0'; a <= '9'; a++){
        for(char b = '0'; b <= '9'; b++){
            printf("%c%c%% ", a, b);
            for(char c = '0'; c <= '9'; c++){
                for(char d = '0'; d <= '9'; d++){
                    const char pin[4] = {a, b, c, d};
                    uint8_t newhash[32];
                    size_t newhash_size = 32;
                    switch (ctx->hashtype){
                        case 4:
                            pbkdf2_hmac_sha256((const unsigned char*)pin, 4, ctx->salt, ctx->salt_size, 10000, newhash, newhash_size);
                            break;
                        case 6:
                            scrypt((const unsigned char*)pin, 4, ctx->salt, ctx->salt_size, 8192, 8, 1, newhash, newhash_size);
                            break;
                        default:
                            fprintf(stderr, "Error: ctx hashtype must be 4/6\n");
                            return false;
                    }

                    if(memcmp(ctx->hash, newhash, newhash_size) == 0){
                        printf("\nPIN find: ");
                        for(int i = 0; i < 4; i++){
                            printf("%c", pin[i]);
                        }
                        printf("\n");
                        return true;
                    }
                }
            }
        }
        printf("\n");
    }
    return false;
}

static void print_help(const char* prog_name){
    printf("Usage: %s [options]", prog_name);
    printf("Options:\n");
    printf("    --salt=<16-hex-digits>, -S      Hard set salt (16-character hexadecimal string, 8-byte salt)\n"
           "                                    if specified, --hash is required\n");
    printf("    --hash=<64-hex-digits>, -H      Hard set hash (64-character hexadecimal string, 32-byte hash)\n"
           "                                    if specified, --salt is required\n");
    printf("    --hash-type=<digit>, -t          Hard set hash-type 4/6 (default: 6)\n");
    printf("    -h, --help                      Show this help message and exit\n");
    printf("    -v, --version                   Show versions information and exit\n");
}

static void print_version(){
    printf("alopin version 1.0\n");
    printf("\n");
    printf("made by rodeka\n");
}

static bool is_hex_string(const char *hex_string, size_t len) {
    if (strlen(hex_string) != len) 
        return false;
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)hex_string[i]))
            return false;
    }
    return true;
}

static int hex_to_bytes(const char* hex_string, unsigned char** byte_sequence, size_t* len){
    size_t hex_length = strlen(hex_string);
    if(hex_length % 2 != 0){
        fprintf(stderr, "Invalid hex string length\n");
        return -1;
    }

    *len = hex_length / 2;
    *byte_sequence = (unsigned char*)malloc(*len);
    if(*byte_sequence == NULL){
        perror("malloc failed");
        return -1;
    }

    for(size_t i = 0; i < *len; i++){
        sscanf(hex_string + 2 * i, "%2hhx", &((*byte_sequence)[i]));
    }

    return 0;
}

int alopinUpdateSteam(ALOPIN_CTX* ctx){
    if (!SteamAPI_Init()) {
        fprintf(stderr, "Error: Cannot init Steam API\n");
        return -1;
    }

    SteamAPICall_t hHandle = SteamUnifiedMessages()->SendMethod("Parental.GetSignedParentalSettings#1", NULL, 0, 0);
    if(hHandle == 0){
        fprintf(stderr, "Error: Cannot send Unified Message\n");
        SteamAPI_Shutdown();
        return -1;
    }

    uint32 unResponseSize = 0;
    EResult eResult = k_EResultFail;

    bool res = SteamUnifiedMessages()->GetMethodResponseInfo(hHandle, &unResponseSize, &eResult);
    using namespace std::chrono_literals;
    for(int i = 0; !res && i < 10; i++){
        std::this_thread::sleep_for(200ms);
        res = SteamUnifiedMessages()->GetMethodResponseInfo(hHandle, &unResponseSize, &eResult);
    }
    if(!res){
        fprintf(stderr, "Error: no data\n");
        SteamAPI_Shutdown();
        return -1;
    }

    uint8* msg_ptr = (uint8*)malloc(unResponseSize);
    uint32 msg_size = unResponseSize;
    if(!SteamUnifiedMessages()->GetMethodResponseData(hHandle, msg_ptr, msg_size, false)){
        fprintf(stderr, "Error: cannot find data\n");
        free(msg_ptr);
        SteamAPI_Shutdown();
        return -1;
    }
    SteamAPI_Shutdown();

    uint8* data_ptr;
    size_t data_size;
    if(proto_extract_field_raw((uint8_t*)msg_ptr, msg_size, 1, &data_ptr, &data_size) != 1){
        fprintf(stderr, "Error: cannot find parental data :(\n");
        free(msg_ptr);
        return -1;
    }
    free(msg_ptr);

    // isEnable Family View?
    uint8_t* isEnable;
    size_t isEnable_size;

    if(proto_extract_field_raw(data_ptr, data_size, 9, &isEnable, &isEnable_size) != 1){
        fprintf(stderr, "Error: cannot find isEnable Parental\n");
        free(data_ptr);
        return -1;
    }

    if(!*isEnable){
        printf("Family View is disabled.\n");
        free(isEnable);
        free(data_ptr);
        return -1;
    }
    free(isEnable);

    // password hash type 4 or 6 ?
    uint8_t* hashtype;
    size_t hashtype_size;
    
    if(proto_extract_field_raw(data_ptr, data_size, 6, &hashtype, &hashtype_size) != 1){
        fprintf(stderr, "Error: cannot find password hash type\n");
        free(data_ptr);
        return -1;
    }

    if(*hashtype != 4 && *hashtype != 6){
        fprintf(stderr, "Error: invalid password hash type: %u\n", *hashtype);
        free(hashtype);
        free(data_ptr);
        return 0;
    }
    ctx->hashtype = *hashtype;
    free(hashtype);

    // salt; salt size = 8
    if(proto_extract_field_raw(data_ptr, data_size, 7, &(ctx->salt), &(ctx->salt_size)) != 1){
        fprintf(stderr, "Error: cannot find salt\n");
        free(data_ptr);
        return -1;
    }

    if(ctx->salt_size != 8){
        fprintf(stderr, "Error: salt size is not 8: %zu\n", ctx->salt_size);
        free(data_ptr);
        return -1;
    }

    // DDDD hash
    if(proto_extract_field_raw(data_ptr, data_size, 8, &(ctx->hash), &(ctx->hash_size)) != 1){
        fprintf(stderr, "Error: cannot find password hash type\n");
        free(data_ptr);
        return -1;
    }
    free(data_ptr);

    if(ctx->hash_size != 32){
        fprintf(stderr, "Error: hash size is not 32: %zu\n", ctx->hash_size);
        return -1;
    }

    return 0;
}

void alopinFree(ALOPIN_CTX* ctx){
    if(ctx->salt)
        free(ctx->salt);
    if(ctx->hash)
        free(ctx->hash);
    if(ctx)
        free(ctx);
}

int alopinUpdateArgc(ALOPIN_CTX* ctx, int argc, char** argv[]){
    ctx->hashtype = 6;

    int show_help = 0;
    int show_ver = 0;

    for (int i = 1; i < argc; i++) {
        char *arg = (*argv)[i];

        // --salt=...
        if (_strnicmp(arg, "--salt=", 7) == 0) {
            char *val = arg + 7;
            if (!is_hex_string(val, SALT_LEN)) {
                fprintf(stderr, "Error: --salt must be exactly %d hex digits\n", SALT_LEN);
                return -1;
            }
            hex_to_bytes(_strdup(val), &(ctx->salt), &(ctx->salt_size));

        // -S <val>
        } else if (_stricmp(arg, "-S") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -S requires an argument\n");
                return -1;
            }
            if (!is_hex_string((*argv)[i + 1], SALT_LEN)) {
                fprintf(stderr, "Error: -S value must be %d hex digits\n", SALT_LEN);
                return -1;
            }
            hex_to_bytes(_strdup((*argv)[++i]), &(ctx->salt), &(ctx->salt_size));

        // --hash=...
        } else if (_strnicmp(arg, "--hash=", 7) == 0) {
            char *val = arg + 7;
            if (!is_hex_string(val, HASH_LEN)) {
                fprintf(stderr, "Error: --hash must be exactly %d hex digits\n", HASH_LEN);
                return -1;
            }
            hex_to_bytes(_strdup(val), &(ctx->hash), &(ctx->hash_size));

        // -H <val>
        } else if (_stricmp(arg, "-H") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -H requires an argument\n");
                return -1;
            }
            if (!is_hex_string((*argv)[i+1], HASH_LEN)) {
                fprintf(stderr, "Error: -H value must be %d hex digits\n", HASH_LEN);
                return -1;
            }
            hex_to_bytes(_strdup((*argv)[++i]), &(ctx->hash), &(ctx->hash_size));

        // --hash-type=...
        } else if (_strnicmp(arg, "--hash-type=", 12) == 0) {
            ctx->hashtype = atoi(arg + 12);
            if (ctx->hashtype != 4 && ctx->hashtype != 6) {
                fprintf(stderr, "Error: --hash-type must be 4 or 6\n");
                return -1;
            }

        // -t <val>
        } else if (_stricmp(arg, "-t") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -t requires an argument\n");
                return -1;
            }
            ctx->hashtype = atoi((*argv)[++i]);
            if (ctx->hashtype != 4 && ctx->hashtype != 6) {
                fprintf(stderr, "Error: -t value must be 4 or 6\n");
                return -1;
            }

        // --help, -h
        } else if (_stricmp(arg, "--help") == 0 || _stricmp(arg, "-h") == 0) {
            show_help = 1;

        // --version, -v
        } else if (_stricmp(arg, "--version") == 0 || _stricmp(arg, "-v") == 0) {
            show_ver = 1;

        } else {
            fprintf(stderr, "Unknown option: %s\n", arg);
            print_help((*argv)[0]);
            return -1;
        }
    }

    if (show_help) {
        print_help((*argv)[0]);
        return 0;
    }
    if (show_ver) {
        print_version();
        return 0;
    }

    if ((ctx->salt && !ctx->hash) || (!ctx->salt && ctx->hash)) {
        fprintf(stderr, "Error: --salt and --hash must be listed together\n");
        return -1;
    }
    return 0;
}

int main(int argc, char* argv[]){
    ALOPIN_CTX* ctx = (ALOPIN_CTX*)malloc(sizeof(ALOPIN_CTX));

    if(argc == 1){
        if(alopinUpdateSteam(ctx)){
            alopinFree(ctx);
        }
    }
        
    if(argc != 1){
        if(alopinUpdateArgc(ctx, argc, &argv)){
            alopinFree(ctx);
        }
    }

    printf("Settings to brute\n");
    printf("Salt: ");
    for(size_t i = 0; i < ctx->salt_size; i++){
        printf("%02X", ctx->salt[i]);
    }
    printf("\n");
    printf("Hash: ");
    for(size_t i = 0; i < ctx->hash_size; i++){
        printf("%02X", ctx->hash[i]);
    }
    printf("\n");

    brute_pin(ctx);

    alopinFree(ctx);
    return 0;
}