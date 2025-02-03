# PAMTest

gcc -fPIC -shared -o pam_example.so pam_example.c -lpam

sudo cp pam_example.so /usr/lib64/security/

sudo systemctl restart sshd

Check the Logs

sudo tail -f /var/log/secure
