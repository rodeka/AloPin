#include <vector>
#include <cstdio>
#include <cstdint>
#include <thread>
#include <chrono>
#include <steam/steam_api.h>

extern "C" {
#include "proto/proto.h"
#include "crypto/scrypt.h"
#include "crypto/pbkdf2.h"
}

bool brute_pass(uint8_t hash_type, uint8_t** salt, uint8_t** hash){
    for(char a = '0'; a <= '9'; a++){
        for(char b = '0'; b <= '9'; b++){
            printf("%c%c%% ", a, b);
            for(char c = '0'; c <= '9'; c++){
                for(char d = '0'; d <= '9'; d++){
                    const char pass[4] = {a, b, c, d};
                    uint8_t newhash[32];
                    uint32_t newhash_size = 32;
                    if(hash_type == 6)
                        scrypt((const uint8_t*)pass, 4, *salt, 8, 8192, 8, 1, newhash, newhash_size);
                    if(hash_type == 4)
                        pbkdf2_hmac_sha256((const uint8_t*)pass, 4, *salt, 8, 10000, newhash_size, newhash);
                    
                    if(memcmp(*hash, newhash, newhash_size) == 0){
                        printf("\nPassword find: ");
                        for(int i = 0; i < 4; i++){
                            printf("%c", pass[i]);
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


int main()
{
    if (!SteamAPI_Init()) {
        fprintf(stderr, "Error: Cannot init Steam API\n");
        return 1;
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
        printf("kek\n");
        free(msg_ptr);
        SteamAPI_Shutdown();
        return -1;
    }

    uint8* data_ptr;
    uint32 data_size;
    if(!extract_field_raw((uint8_t*)msg_ptr, msg_size, 1, &data_ptr, &data_size)){
        fprintf(stderr, "Error: cannot find parental data :(\n");
        free(msg_ptr);
        return -1;
    }
    free(msg_ptr);

    // isEnable Family View?
    uint8_t* isEnable = false;
    uint32_t isEnable_size;

    if(!extract_field_raw(data_ptr, data_size, 9, &isEnable, &isEnable_size)){
        fprintf(stderr, "Error: cannot find isEnable Parental\n");
        free(data_ptr);
        SteamAPI_Shutdown();
        return -1;
    }

    if(!*isEnable){
        printf("Family View disabled.\n");

        free(data_ptr);
        return(0);
    }
    free(isEnable);

    // password hash type 4 or 6 ?
    uint8_t* passhashtype;
    uint32_t passhashtype_size;
    
    if(!extract_field_raw(data_ptr, data_size, 6, &passhashtype, &passhashtype_size)){
        fprintf(stderr, "Error: cannot find password hash type\n");
        free(data_ptr);
        SteamAPI_Shutdown();
        return -1;
    }

    if(*passhashtype != 4 && *passhashtype != 6){
        fprintf(stderr, "Error: invalid password hash type: %u\n", *passhashtype);
        free(passhashtype);
        free(data_ptr);
        return 0;
    }
    else{
        printf("HashType: %u\n", *passhashtype);
    }

    // salt; salt size = 8!
    uint8_t* salt;
    uint32_t salt_size;

    if(!extract_field_raw(data_ptr, data_size, 7, &salt, &salt_size)){
        fprintf(stderr, "Error: cannot find salt\n");
        free(passhashtype);
        free(data_ptr);
        SteamAPI_Shutdown();
        return -1;
    }

    if(salt_size != 8){
        fprintf(stderr, "Error: salt size is not 8: %u\n", salt_size);
        free(salt);
        free(passhashtype);
        free(data_ptr);
        SteamAPI_Shutdown();
        return -1;
    }

    printf("Salt find: ");
    for(int i = 0; i < salt_size; i++){
        printf("%02X", salt[i]);
    }
    printf("\n");


    // DDDD passhash
    uint8_t* passhash;
    uint32_t passhash_size;

    if(!extract_field_raw(data_ptr, data_size, 8, &passhash, &passhash_size)){
        fprintf(stderr, "Error: cannot find password hash type\n");
        free(salt);
        free(passhashtype);
        free(data_ptr);
        SteamAPI_Shutdown();
        return -1;
    }

    if(passhash_size != 32){
        fprintf(stderr, "Error: passhash size is not 32: %u\n", passhash_size);
        free(passhash);
        free(salt);
        free(passhashtype);
        free(data_ptr);
        SteamAPI_Shutdown();
        return -1;
    }

    printf("PassHash find: ");
    for(int i = 0; i < passhash_size; i++){
        printf("%02X", passhash[i]);
    }
    printf("\n");

    brute_pass(*passhashtype, &salt, &passhash);

    free(passhash);
    free(salt);
    free(passhashtype);
    free(data_ptr);
    SteamAPI_Shutdown();

    system("pause");
    return 0;
}