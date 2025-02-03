# PAMTest

gcc -fPIC -shared -o pam_okta.so pam_okta.c -lpam -lcurl

sudo cp pam_example.so /usr/lib64/security/

sudo systemctl restart sshd

Check the Logs

sudo tail -f /var/log/secure

Install GCC Compiler if not present

sudo yum groupinstall "Development Tools" -y

install libcurl development headers

sudo yum install libcurl-devel

Verify Installation

After installing libcurl-devel, verify that the header file is present:

ls /usr/include/curl/curl.h

