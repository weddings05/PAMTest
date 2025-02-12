// pam_okta_web.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <syslog.h>
#include <curl/curl.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>

#define CONFIG_FILE "/etc/exceed/okta-config.txt"
#define DEBUG_LOG "/var/log/okta_pam_debug.log"
#define MAX_LINE 1024
#define MAX_RESPONSE 4096

// Structure declarations (same as before)
struct MemoryStruct {
    char* memory;
    size_t size;
};

struct OktaConfig {
    char issuer[MAX_LINE];
    char client_id[MAX_LINE];
    char client_secret[MAX_LINE];
    char token_endpoint[MAX_LINE];
};

// Debug logging function
static void debug_log(const char* format, ...) {
    FILE* fp = fopen(DEBUG_LOG, "a");
    if (!fp) {
        syslog(LOG_ERR, "Cannot open debug log: %s", strerror(errno));
        return;
    }

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(fp, "[%s] ", timestamp);
    
    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    
    fprintf(fp, "\n");
    fclose(fp);
}

// CURL write callback
static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;

    char* ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        debug_log("Failed to allocate memory for CURL response");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

// Function to get PAM conversation function
static int get_conversation(pam_handle_t* pamh, const struct pam_conv** conv) {
    int ret = pam_get_item(pamh, PAM_CONV, (const void**)conv);
    if (ret != PAM_SUCCESS) {
        debug_log("Failed to get PAM conversation: %s", pam_strerror(pamh, ret));
        return ret;
    }
    return PAM_SUCCESS;
}

// Function to prompt user through PAM conversation
static int prompt_user(pam_handle_t* pamh, int msg_style, const char* prompt, char** response) {
    const struct pam_conv* conv;
    struct pam_message msg;
    const struct pam_message* msgp;
    struct pam_response* resp;
    int ret;

    debug_log("Displaying prompt: %s", prompt);

    ret = get_conversation(pamh, &conv);
    if (ret != PAM_SUCCESS) {
        debug_log("Failed to get conversation function");
        return ret;
    }

    msg.msg_style = msg_style;
    msg.msg = prompt;
    msgp = &msg;
    
    ret = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (ret != PAM_SUCCESS) {
        debug_log("Conversation failed: %d", ret);
        return ret;
    }

    if (resp == NULL || resp[0].resp == NULL) {
        debug_log("No response received from user");
        free(resp);
        return PAM_CONV_ERR;
    }

    *response = strdup(resp[0].resp);
    debug_log("Received response from user (length: %zu)", strlen(resp[0].resp));
    
    // Clear sensitive data
    memset(resp[0].resp, 0, strlen(resp[0].resp));
    free(resp[0].resp);
    free(resp);

    return PAM_SUCCESS;
}

// Read Okta configuration
static int read_config(struct OktaConfig* config) {
    debug_log("Reading Okta configuration from %s", CONFIG_FILE);
    
    FILE* fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        debug_log("Cannot open config file: %s", strerror(errno));
        return -1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char* key = strtok(line, "=");
        char* value = strtok(NULL, "\n");
        
        if (key && value) {
            while (*value == ' ') value++;  // Trim leading spaces
            
            if (strcmp(key, "issuer") == 0) {
                strncpy(config->issuer, value, MAX_LINE - 1);
                debug_log("Found issuer: %s", config->issuer);
            } else if (strcmp(key, "client_id") == 0) {
                strncpy(config->client_id, value, MAX_LINE - 1);
                debug_log("Found client_id: %s", config->client_id);
            } else if (strcmp(key, "client_secret") == 0) {
                strncpy(config->client_secret, value, MAX_LINE - 1);
                debug_log("Found client_secret: [REDACTED]");
            } else if (strcmp(key, "token_endpoint") == 0) {
                strncpy(config->token_endpoint, value, MAX_LINE - 1);
                debug_log("Found token_endpoint: %s", config->token_endpoint);
            }
        }
    }
    fclose(fp);
    debug_log("Finished reading configuration");
    return 0;
}

// Function to handle MFA challenge
static int handle_mfa_challenge(pam_handle_t* pamh, CURL* curl, 
                              struct MemoryStruct* chunk, struct OktaConfig* config) {
    debug_log("MFA challenge detected, requesting code from user");
    
    char* mfa_code = NULL;
    int ret;

    ret = prompt_user(pamh, PAM_PROMPT_ECHO_ON, 
                     "Enter your Okta MFA code: ", &mfa_code);
    if (ret != PAM_SUCCESS || !mfa_code) {
        debug_log("Failed to get MFA code from user");
        return PAM_AUTH_ERR;
    }

    debug_log("Received MFA code, verifying with Okta");

    // Clear previous response
    free(chunk->memory);
    chunk->memory = malloc(1);
    chunk->size = 0;

    // Prepare MFA verification request
    char post_data[MAX_LINE * 2];
    snprintf(post_data, sizeof(post_data),
             "factor_token=%s&client_id=%s&client_secret=%s",
             mfa_code, config->client_id, config->client_secret);

    // Clean up sensitive data
    memset(mfa_code, 0, strlen(mfa_code));
    free(mfa_code);

    char mfa_url[MAX_LINE];
    snprintf(mfa_url, sizeof(mfa_url), "%s/v1/factors/verify", config->issuer);
    
    debug_log("Sending MFA verification request to: %s", mfa_url);
    
    curl_easy_setopt(curl, CURLOPT_URL, mfa_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        debug_log("MFA verification failed: %s", curl_easy_strerror(res));
        return PAM_AUTH_ERR;
    }

    debug_log("MFA verification response received (length: %zu)", chunk->size);

    if (strstr(chunk->memory, "access_token")) {
        debug_log("MFA verification successful");
        return PAM_SUCCESS;
    }

    debug_log("MFA verification failed: Invalid response");
    return PAM_AUTH_ERR;
}

// Authenticate with Okta
static int okta_authenticate(pam_handle_t* pamh, const char* username, 
                           const char* password, struct OktaConfig* config) {
    debug_log("Starting Okta authentication for user: %s", username);
    
    CURL* curl;
    CURLcode res;
    struct MemoryStruct chunk;
    long http_code = 0;
    int ret = PAM_AUTH_ERR;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if (!curl) {
        debug_log("Failed to initialize CURL");
        free(chunk.memory);
        return PAM_SYSTEM_ERR;
    }

    debug_log("Preparing Okta authentication request");

    // Prepare POST data
    char post_data[MAX_LINE * 3];
    snprintf(post_data, sizeof(post_data),
             "grant_type=password&username=%s&password=%s&"
             "client_id=%s&client_secret=%s&scope=openid profile",
             username, password, config->client_id, config->client_secret);

    curl_easy_setopt(curl, CURLOPT_URL, config->token_endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    debug_log("Sending authentication request to: %s", config->token_endpoint);
    
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    debug_log("Received response from Okta (HTTP code: %ld, response length: %zu)", 
              http_code, chunk.size);

    if (res != CURLE_OK) {
        debug_log("CURL request failed: %s", curl_easy_strerror(res));
        ret = PAM_AUTH_ERR;
    } else if (http_code == 200 && strstr(chunk.memory, "access_token")) {
        debug_log("Authentication successful");
        ret = PAM_SUCCESS;
    } else if (strstr(chunk.memory, "mfa_required")) {
        debug_log("MFA required, initiating MFA flow");
        ret = handle_mfa_challenge(pamh, curl, &chunk, config);
    } else {
        debug_log("Authentication failed: Invalid response");
        ret = PAM_AUTH_ERR;
    }

    free(chunk.memory);
    curl_easy_cleanup(curl);
    debug_log("Completed Okta authentication attempt with result: %d", ret);
    return ret;
}

// Main PAM authentication function
PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    debug_log("Starting PAM Okta authentication module");
    
    char* okta_username = NULL;
    char* okta_password = NULL;
    int ret;
    struct OktaConfig config;

    // Read Okta configuration
    if (read_config(&config) != 0) {
        debug_log("Failed to read Okta configuration");
        return PAM_IGNORE;  // Allow fallthrough to next module
    }

    // Prompt for Okta username
    ret = prompt_user(pamh, PAM_PROMPT_ECHO_ON,
                     "Okta username: ", &okta_username);
    if (ret != PAM_SUCCESS || !okta_username) {
        debug_log("Failed to get Okta username");
        return PAM_IGNORE;
    }

    // Prompt for Okta password
    ret = prompt_user(pamh, PAM_PROMPT_ECHO_OFF,
                     "Okta password: ", &okta_password);
    if (ret != PAM_SUCCESS || !okta_password) {
        debug_log("Failed to get Okta password");
        if (okta_username) {
            memset(okta_username, 0, strlen(okta_username));
            free(okta_username);
        }
        return PAM_IGNORE;
    }

    // Authenticate with Okta
    ret = okta_authenticate(pamh, okta_username, okta_password, &config);

    // Clean up sensitive data
    if (okta_username) {
        memset(okta_username, 0, strlen(okta_username));
        free(okta_username);
    }
    if (okta_password) {
        memset(okta_password, 0, strlen(okta_password));
        free(okta_password);
    }

    // Convert PAM_AUTH_ERR to PAM_IGNORE for 'sufficient' behavior
    if (ret != PAM_SUCCESS) {
        debug_log("Authentication failed, allowing fallthrough to next module");
        return PAM_IGNORE;
    }

    debug_log("Authentication completed successfully");
    return PAM_SUCCESS;
}

// Required PAM module functions
PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    return PAM_SUCCESS;
}
