I'll help you create a custom PAM module for Okta authentication with fallback. Here's the complete implementation:

1. First, create the PAM module source code:

```bash
sudo vi /usr/src/pam_okta.c
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define OKTA_API_URL "https://your-domain.okta.com/api/v1/authn"
#define MAX_USERNAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 256

// Struct to store CURL response
struct curl_response {
    char *data;
    size_t size;
};

// Callback function for CURL
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_response *resp = (struct curl_response *)userp;

    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (!ptr) {
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
    char* local_username = strdup(email);
    char* at_sign = strchr(local_username, '@');
    if (at_sign) {
        *at_sign = '\0';
    }
    return local_username;
}

// Check if local user exists
static int user_exists(const char* username) {
    FILE* passwd = fopen("/etc/passwd", "r");
    if (!passwd) {
        return 0;
    }

    char line[512];
    int exists = 0;
    while (fgets(line, sizeof(line), passwd)) {
        char* user = strtok(line, ":");
        if (user && strcmp(user, username) == 0) {
            exists = 1;
            break;
        }
    }
    fclose(passwd);
    return exists;
}

// Authenticate with Okta
static int authenticate_with_okta(const char* username, const char* password) {
    CURL *curl;
    CURLcode res;
    struct curl_response resp = {0};
    int auth_success = 0;

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

        curl_easy_setopt(curl, CURLOPT_URL, OKTA_API_URL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            json_object *json_resp = json_tokener_parse(resp.data);
            json_object *status;
            if (json_object_object_get_ex(json_resp, "status", &status)) {
                const char *status_str = json_object_get_string(status);
                if (strcmp(status_str, "SUCCESS") == 0) {
                    auth_success = 1;
                }
            }
            json_object_put(json_resp);
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    free(resp.data);
    json_object_put(json_payload);
    return auth_success;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    const char *password = NULL;
    int retval;

    // Get username
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    // Extract local username if it's an email
    char *local_username = extract_local_username(username);
    
    // Check if local user exists
    if (!user_exists(local_username)) {
        free(local_username);
        return PAM_USER_UNKNOWN;
    }

    // Get password
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (retval != PAM_SUCCESS) {
        free(local_username);
        return retval;
    }

    // If username contains @, try Okta authentication
    if (strchr(username, '@')) {
        if (authenticate_with_okta(username, password)) {
            // Set local username for the session
            pam_set_item(pamh, PAM_USER, local_username);
            free(local_username);
            return PAM_SUCCESS;
        }
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

2. Create a Makefile:

```bash
sudo vi /usr/src/Makefile
```

```makefile
CC=gcc
CFLAGS=-fPIC -fno-stack-protector -Wall
LDFLAGS=-shared
LIBS=-lpam -lcurl -ljson-c

TARGET=pam_okta.so
SOURCES=pam_okta.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

install: $(TARGET)
	install -d /lib64/security
	install -m 755 $(TARGET) /lib64/security/

clean:
	rm -f $(TARGET)
```

3. Install required dependencies:

For RHEL/CentOS:
```bash
sudo yum install gcc make pam-devel curl-devel json-c-devel
```

For Ubuntu/Debian:
```bash
sudo apt-get install gcc make libpam0g-dev libcurl4-openssl-dev libjson-c-dev
```

4. Build and install the module:
```bash
cd /usr/src
sudo make
sudo make install
```

5. Configure PAM for SSHD. Edit `/etc/pam.d/sshd`:
```
# Add at the beginning of auth section
auth        [success=1 default=ignore]     pam_okta.so
auth        required     pam_sepermit.so
auth        substack     password-auth
auth        include      postlogin

# Rest of the configuration remains the same
```

6. Configure SSHD. Edit `/etc/ssh/sshd_config`:
```
UsePAM yes
PasswordAuthentication yes
ChallengeResponseAuthentication yes
```

7. Create a configuration file for Okta settings (optional):
```bash
sudo vi /etc/okta.conf
```

```ini
[okta]
api_url=https://your-domain.okta.com/api/v1/authn
```

8. Restart SSHD:
```bash
sudo systemctl restart sshd
```

Now you can test:
```bash
# Test with Okta email
ssh user@example.com@hostname

# Test with local user
ssh localuser@hostname
```

The authentication flow will be:
1. User connects with email address
2. PAM module:
   - Extracts local username from email
   - Verifies local user exists
   - If exists, tries Okta authentication
   - If Okta fails, falls back to local authentication
3. If using local username:
   - Goes directly to local authentication

For debugging:
1. Add logging to syslog in the PAM module:
```c
#include <syslog.h>

// Add in key points:
syslog(LOG_AUTH|LOG_DEBUG, "PAM_OKTA: Attempting authentication for %s", username);
```

2. Watch logs:
```bash
tail -f /var/log/auth.log
```

To make changes to the module:
1. Edit the source code
2. Rebuild and reinstall:
```bash
cd /usr/src
sudo make clean
sudo make
sudo make install
```

Remember to:
1. Replace `your-domain.okta.com` with your actual Okta domain
2. Secure your PAM module file:
```bash
sudo chmod 755 /lib64/security/pam_okta.so
sudo chown root:root /lib64/security/pam_okta.so
```

The module includes error handling and memory management, but you might want to add more extensive logging and error handling based on your needs.​​​​​​​​​​​​​​​​

  
