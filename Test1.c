Here's the complete, modified PAM module code with all necessary components to handle different passwords for Okta and Linux authentication:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>

#define OKTA_API_URL "https://your-domain.okta.com/api/v1/authn"
#define MAX_USERNAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 256
#define CONFIG_FILE "/etc/okta_pam.conf"
#define LOG_PREFIX "PAM_OKTA"

// Structure to store CURL response
struct curl_response {
    char *data;
    size_t size;
};

// Structure to store configuration
struct okta_config {
    char api_url[256];
    int debug;
};

// Global configuration
static struct okta_config config = {
    .api_url = OKTA_API_URL,
    .debug = 0
};

// Debug logging function
static void debug_log(const char *format, ...) {
    if (config.debug) {
        va_list args;
        va_start(args, format);
        vsyslog(LOG_AUTH|LOG_DEBUG, format, args);
        va_end(args);
    }
}

// Load configuration from file
static void load_config(void) {
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        syslog(LOG_AUTH|LOG_WARNING, "%s: Could not open config file %s: %s", 
               LOG_PREFIX, CONFIG_FILE, strerror(errno));
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");
        
        if (key && value) {
            // Remove whitespace
            while (*key && isspace(*key)) key++;
            while (*value && isspace(*value)) value++;
            
            if (strcmp(key, "api_url") == 0) {
                strncpy(config.api_url, value, sizeof(config.api_url) - 1);
            } else if (strcmp(key, "debug") == 0) {
                config.debug = atoi(value);
            }
        }
    }
    fclose(fp);
}

// CURL write callback
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_response *resp = (struct curl_response *)userp;

    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (!ptr) {
        syslog(LOG_AUTH|LOG_ERR, "%s: Memory allocation failed", LOG_PREFIX);
        return 0;
    }

    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;

    return realsize;
}

// Extract local username from email
static char* extract_local_username(const char* email) {
    if (!email) return NULL;
    
    char* local_username = strdup(email);
    if (!local_username) {
        syslog(LOG_AUTH|LOG_ERR, "%s: Memory allocation failed", LOG_PREFIX);
        return NULL;
    }

    char* at_sign = strchr(local_username, '@');
    if (at_sign) {
        *at_sign = '\0';
    }
    
    debug_log("%s: Extracted local username '%s' from '%s'", LOG_PREFIX, local_username, email);
    return local_username;
}

// Check if local user exists
static int user_exists(const char* username) {
    if (!username) return 0;

    struct passwd *pw = getpwnam(username);
    int exists = (pw != NULL);
    
    debug_log("%s: Checking if user '%s' exists: %s", 
              LOG_PREFIX, username, exists ? "yes" : "no");
    
    return exists;
}

// Authenticate with Okta
static int authenticate_with_okta(const char* username, const char* password) {
    if (!username || !password) return 0;

    CURL *curl;
    CURLcode res;
    struct curl_response resp = {0};
    int auth_success = 0;
    long http_code = 0;

    debug_log("%s: Attempting Okta authentication for user '%s'", LOG_PREFIX, username);

    // Prepare JSON payload
    json_object *json_payload = json_object_new_object();
    json_object_object_add(json_payload, "username", json_object_new_string(username));
    json_object_object_add(json_payload, "password", json_object_new_string(password));
    const char *json_string = json_object_to_json_string(json_payload);

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, config.api_url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (res == CURLE_OK && http_code == 200) {
            json_object *json_resp = json_tokener_parse(resp.data);
            if (json_resp) {
                json_object *status;
                if (json_object_object_get_ex(json_resp, "status", &status)) {
                    const char *status_str = json_object_get_string(status);
                    auth_success = (strcmp(status_str, "SUCCESS") == 0);
                    debug_log("%s: Okta authentication status: %s", LOG_PREFIX, status_str);
                }
                json_object_put(json_resp);
            }
        } else {
            syslog(LOG_AUTH|LOG_ERR, "%s: Okta API call failed: %s (HTTP %ld)", 
                   LOG_PREFIX, curl_easy_strerror(res), http_code);
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    if (resp.data) {
        free(resp.data);
    }
    json_object_put(json_payload);

    return auth_success;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    char *okta_password = NULL;
    int retval;

    // Load configuration
    load_config();

    // Initialize logging
    openlog("pam_okta", LOG_PID, LOG_AUTH);

    // Get username
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_AUTH|LOG_ERR, "%s: Failed to get username", LOG_PREFIX);
        return retval;
    }

    debug_log("%s: Processing authentication for user: %s", LOG_PREFIX, username);

    // Extract local username if it's an email
    char *local_username = extract_local_username(username);
    if (!local_username) {
        return PAM_SYSTEM_ERR;
    }

    // Check if local user exists
    if (!user_exists(local_username)) {
        syslog(LOG_AUTH|LOG_ERR, "%s: Local user %s does not exist", LOG_PREFIX, local_username);
        free(local_username);
        return PAM_USER_UNKNOWN;
    }

    // If username contains @, try Okta authentication
    if (strchr(username, '@')) {
        // Get Okta password
        const char *prompt = "Okta Password: ";
        char *resp = NULL;
        retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "%s", prompt);
        
        if (retval != PAM_SUCCESS || !resp) {
            syslog(LOG_AUTH|LOG_ERR, "%s: Failed to get Okta password", LOG_PREFIX);
            free(local_username);
            return PAM_AUTH_ERR;
        }

        okta_password = strdup(resp);
        free(resp);  // Free the response from pam_prompt

        if (!okta_password) {
            syslog(LOG_AUTH|LOG_ERR, "%s: Memory allocation failed", LOG_PREFIX);
            free(local_username);
            return PAM_SYSTEM_ERR;
        }

        debug_log("%s: Attempting Okta authentication for %s", LOG_PREFIX, username);

        if (authenticate_with_okta(username, okta_password)) {
            syslog(LOG_AUTH|LOG_INFO, "%s: Okta authentication successful for %s", LOG_PREFIX, username);
            
            // Set local username for the session
            pam_set_item(pamh, PAM_USER, local_username);
            
            // Cleanup
            memset(okta_password, 0, strlen(okta_password));
            free(okta_password);
            free(local_username);
            
            return PAM_SUCCESS;
        }

        // Cleanup
        memset(okta_password, 0, strlen(okta_password));
        free(okta_password);
        syslog(LOG_AUTH|LOG_INFO, "%s: Okta authentication failed, falling back to local authentication", LOG_PREFIX);
    }

    free(local_username);
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

Create the configuration file:
```bash
sudo vi /etc/okta_pam.conf
```

```ini
api_url=https://your-domain.okta.com/api/v1/authn
debug=1
```

Create the Makefile:
```makefile
CC=gcc
CFLAGS=-fPIC -fno-stack-protector -Wall `pkg-config --cflags json-c`
LDFLAGS=-shared
LIBS=-lpam -lcurl `pkg-config --libs json-c`

TARGET=pam_okta.so
SOURCES=pam_okta.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

install: $(TARGET)
	install -d /lib64/security
	install -m 755 $(TARGET) /lib64/security/
	install -m 600 okta_pam.conf /etc/okta_pam.conf

clean:
	rm -f $(TARGET)
```

Configure PAM (`/etc/pam.d/sshd`):
```
# Okta authentication with fallback
auth        [success=1 default=ignore]     pam_okta.so
auth        required     pam_sepermit.so
auth        substack     password-auth
auth        include      postlogin

# Rest of your existing configuration
-auth       optional     pam_reauthorize.so prepare
account     required     pam_nologin.so
account     include      password-auth
password    include      password-auth
session     required     pam_selinux.so close
session     required     pam_loginuid.so
session     required     pam_selinux.so open env_params
session     required     pam_namespace.so
session     optional     pam_keyinit.so force revoke
session     include      password-auth
session     include      postlogin
session     optional     pam_reauthorize.so prepare
```

Build and install:
```bash
# Install dependencies
sudo yum install gcc make pam-devel curl-devel json-c-devel

# Build and install
cd /usr/src
sudo make
sudo make install

# Set permissions
sudo chmod 755 /lib64/security/pam_okta.so
sudo chown root:root /lib64/security/pam_okta.so
sudo chmod 600 /etc/okta_pam.conf
sudo chown root:root /etc/okta_pam.conf

# Restart sshd
sudo systemctl restart sshd
```

Test the authentication:
```bash
# Test with Okta email
ssh user@example.com@hostname
Okta Password: (enter Okta password)
Password: (enter Linux password if Okta fails)

# Test with local user
ssh localuser@hostname
Password: (enter Linux password)
```

Monitor logs:
```bash
tail -f /var/log/auth.log | grep PAM_OKTA
```

This implementation includes:
- Proper password prompting for both Okta and local auth
- Extensive error handling and logging
- Configuration file support
- Memory cleanup for sensitive data
- Debug logging option
- Proper PAM chain handling for authentication fallback​​​​​​​​​​​​​​​​
