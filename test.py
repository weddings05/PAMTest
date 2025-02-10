import os
import sys
import json
import requests
import syslog
from datetime import datetime
from typing import Optional, Dict, Any, Tuple

def log(message: str) -> None:
    """Log messages to syslog and optional debug file"""
    syslog.syslog(syslog.LOG_AUTH, f"pam_okta: {message}")
    if os.environ.get('PAM_OKTA_DEBUG'):
        with open('/var/log/pam_okta_debug.log', 'a') as f:
            f.write(f"{datetime.now()}: {message}\n")

class OktaAuthenticator:
    def __init__(self, config_path: str = '/etc/pam_okta.conf'):
        try:
            with open(config_path) as f:
                self.config = json.load(f)
            
            self.okta_domain = self.config['okta_domain']
            self.api_token = self.config['api_token']
            self.client_id = self.config['client_id']  # OIDC App Client ID
            
        except Exception as e:
            log(f"Error loading configuration: {str(e)}")
            raise
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Authenticate user with Okta's Authentication API
        Returns: (success, user_id)
        """
        try:
            # Primary authentication
            auth_url = f"https://{self.okta_domain}/api/v1/authn"
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'username': username,
                'password': password,
                'options': {
                    'multiOptionalFactorEnroll': False,
                    'warnBeforePasswordExpired': True
                }
            }
            
            response = requests.post(auth_url, headers=headers, json=payload)
            
            if response.status_code != 200:
                log(f"Authentication failed: {response.status_code}")
                return False, None
            
            auth_response = response.json()
            
            # Check authentication status
            if auth_response['status'] != 'SUCCESS':
                log(f"Authentication status: {auth_response['status']}")
                return False, None
            
            # Extract user ID from response
            user_id = auth_response.get('_embedded', {}).get('user', {}).get('id')
            if not user_id:
                log("No user ID in authentication response")
                return False, None
            
            return True, user_id
            
        except Exception as e:
            log(f"Error during authentication: {str(e)}")
            return False, None
    
    def verify_user_status(self, user_id: str) -> bool:
        """Verify user is ACTIVE in Okta"""
        try:
            headers = {
                'Accept': 'application/json',
                'Authorization': f'SSWS {self.api_token}'
            }
            
            user_url = f"https://{self.okta_domain}/api/v1/users/{user_id}"
            response = requests.get(user_url, headers=headers)
            
            if response.status_code != 200:
                log(f"Failed to get user status: {response.status_code}")
                return False
            
            user_data = response.json()
            return user_data['status'] == 'ACTIVE'
            
        except Exception as e:
            log(f"Error checking user status: {str(e)}")
            return False
    
    def verify_app_assignment(self, user_id: str) -> bool:
        """Verify user is assigned to the OIDC application"""
        try:
            headers = {
                'Accept': 'application/json',
                'Authorization': f'SSWS {self.api_token}'
            }
            
            # Check app assignment
            app_url = f"https://{self.okta_domain}/api/v1/apps/{self.client_id}/users/{user_id}"
            response = requests.get(app_url, headers=headers)
            
            # 200 means user is assigned, 404 means not assigned
            if response.status_code == 200:
                return True
            elif response.status_code == 404:
                log(f"User not assigned to application")
                return False
            else:
                log(f"Error checking app assignment: {response.status_code}")
                return False
            
        except Exception as e:
            log(f"Error verifying app assignment: {str(e)}")
            return False
    
    def check_group_membership(self, user_id: str) -> bool:
        """Optional: Check if user belongs to required groups"""
        if not self.config.get('required_groups'):
            return True
            
        try:
            headers = {
                'Accept': 'application/json',
                'Authorization': f'SSWS {self.api_token}'
            }
            
            # Get user's groups
            groups_url = f"https://{self.okta_domain}/api/v1/users/{user_id}/groups"
            response = requests.get(groups_url, headers=headers)
            
            if response.status_code != 200:
                log(f"Error getting user groups: {response.status_code}")
                return False
            
            user_groups = [group['profile']['name'] for group in response.json()]
            required_groups = self.config['required_groups']
            
            # Check if user is in any of the required groups
            return any(group in user_groups for group in required_groups)
            
        except Exception as e:
            log(f"Error checking group membership: {str(e)}")
            return False

def pam_sm_authenticate(pamh, flags, argv):
    try:
        # Initialize Okta authentication
        okta = OktaAuthenticator()
        
        # Get username
        try:
            username = pamh.get_user()
        except pamh.exception as e:
            return pamh.PAM_USER_UNKNOWN
        
        # Get password
        try:
            resp = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Password: "))
            password = resp.resp
        except pamh.exception as e:
            return pamh.PAM_AUTH_ERR
        
        # Step 1: Primary authentication
        auth_success, user_id = okta.authenticate_user(username, password)
        if not auth_success or not user_id:
            log(f"Authentication failed for user {username}")
            return pamh.PAM_AUTH_ERR
        
        # Step 2: Verify user is active
        if not okta.verify_user_status(user_id):
            log(f"User {username} is not active")
            return pamh.PAM_AUTH_ERR
        
        # Step 3: Verify application assignment
        if not okta.verify_app_assignment(user_id):
            log(f"User {username} not assigned to application")
            return pamh.PAM_AUTH_ERR
        
        # Step 4: Optional group membership check
        if not okta.check_group_membership(user_id):
            log(f"User {username} not in required groups")
            return pamh.PAM_AUTH_ERR
        
        return pamh.PAM_SUCCESS
        
    except Exception as e:
        log(f"Authentication error: {str(e)}")
        return pamh.PAM_AUTH_ERR

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_AUTH_ERR
