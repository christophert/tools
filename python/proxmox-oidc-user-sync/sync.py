import proxmoxer
import ldap
import os
import sys
from pprint import pprint
from dotenv import load_dotenv

load_dotenv()

try:
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    ldapobj = ldap.initialize(os.environ.get('LDAP_URI'))
    ldapobj.simple_bind_s(os.environ.get('LDAP_USER'), os.environ.get('LDAP_PASS'))
except ldap.INVALID_CREDENTIALS:
    print("Invalid credentials")
    sys.exit(1)
except ldap.LDAPError as e:
    print(e)
    sys.exit(1)

# get LDAP membership
result = ldapobj.search_s('dc=glitch,dc=rogue,dc=lab',
                          ldap.SCOPE_SUBTREE,
                          '(&(objectClass=ipausergroup)(|(cn=flt_*)(cn=pve_*)))',
                          ['member'])

pprint(result)