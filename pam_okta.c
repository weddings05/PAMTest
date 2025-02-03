#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <syslog.h> // Include syslog for logging

#define OKTA_API_URL "https://YOUR_OKTA_DOMAIN.okta.com/api/v1/authn"
#define OKTA_TOKEN_URL "https://YOUR_OKTA_DOMAIN.okta.com/oauth2/v1/token" // Token URL
#define OKTA_CLIENT_ID "YOUR_OKTA_CLIENT_ID"
#define OKTA_CLIENT_SECRET "YOUR_OKTA_CLIENT_SECRET"
#define OKTA_SCOPE "openid"

// Function to write response data
static size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    strncat(data, (char *)ptr, size * nmemb);
    return size * nmemb;
}

// Function to retrieve Okta token
int get_okta_token(char *token, size_t token_size) {
    CURL *curl;
    CURLcode res;
    char post_data[256];
    char response[4096] = {0};

    // Prepare the POST data
    snprintf(post_data, sizeof(post_data), "grant_type=client_credentials&client_id=%s&client_secret=%s&scope=%s",
             OKTA_CLIENT_ID, OKTA_CLIENT_SECRET, OKTA_SCOPE);

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

        curl_easy_setopt(curl, CURLOPT_URL, OKTA_TOKEN_URL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            syslog(LOG_ERR, "PAM_OKTA: curl_easy_perform() failed: %s", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            return 0;
        }

        // Parse the token from the response
        char *token_start = strstr(response, "\"access_token\":\"");
        if(token_start) {
            token_start += strlen("\"access_token\":\"");
            char *token_end = strchr(token_start, '\"');
            if(token_end) {
                size_t token_length = token_end - token_start;
                if(token_length < token_size) {
                    strncpy(token, token_start, token_length);
                    token[token_length] = '\0';
                } else {
                    syslog(LOG_ERR, "PAM_OKTA: Token buffer size too small");
                    curl_easy_cleanup(curl);
                    return 0;
                }
            }
        }

        curl_easy_cleanup(curl);
        return 1; // Token retrieval successful
    }

    return 0; // Token retrieval failed
}

// Function to perform Okta authentication
int okta_authenticate(const char *username, const char *password) {
    CURL *curl;
    CURLcode res;
    char post_data[256];
    char response[4096] = {0};
    char token[4096] = {0};

    // Log authentication attempt
    syslog(LOG_INFO, "PAM_OKTA: Attempting to authenticate user: %s", username);

    // Retrieve Okta token
    if(!get_okta_token(token, sizeof(token))) {
        syslog(LOG_ERR, "PAM_OKTA: Failed to retrieve Okta token");
        return 0; // Authentication failed
    }

    // Prepare the JSON payload
    snprintf(post_data, sizeof(post_data), "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        char auth_header
