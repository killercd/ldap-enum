#!/usr/bin/python
import subprocess
import argparse
import sys
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, Tls
from pathlib import Path
from ldap3 import BASE
import ssl

#tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

script_dir = Path(__file__).resolve().parent
env = Environment(loader=FileSystemLoader(script_dir / 'r_templates'))
template = env.get_template('full_accounts.html')

FLAGS = [
    (0x00000002, "ACCOUNTDISABLE"),
    (0x00000008, "HOMEDIR_REQUIRED"),
    (0x00000010, "LOCKOUT"),
    (0x00000020, "PASSWORD_NOT_REQUIRED"),
    (0x00000040, "PASSWORD_CANT_CHANGE"),   # not directly stored in uac; usually via ACL
    (0x00000080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x00000100, "TEMP_DUPLICATE_ACCOUNT"),
    (0x00000200, "NORMAL_ACCOUNT"),
    (0x00000800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x00001000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x00002000, "SERVER_TRUST_ACCOUNT"),
    (0x00010000, "DONT_EXPIRE_PASSWORD"),
    (0x00020000, "MNS_LOGON_ACCOUNT"),
    (0x00040000, "SMARTCARD_REQUIRED"),
    (0x00080000, "TRUSTED_FOR_DELEGATION"),
    (0x00100000, "NOT_DELEGATED"),
    (0x00200000, "USE_DES_KEY_ONLY"),
    (0x00400000, "DONT_REQUIRE_PREAUTH"),
    (0x00800000, "PASSWORD_EXPIRED"),
    (0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
]


def decode_uac(uac):
    if isinstance(uac, list):
        uac = int(uac[0])
    else:
        uac = int(uac)
    flags = [name for bit, name in FLAGS if (uac & bit) == bit]
    return " | ".join(flags) if flags else "NONE"

def decode_instance_type(value):
    flags = []
    if isinstance(value, list):
        value = int(value[0])
    else:
        value = int(value)
    if value & 0x01:
        flags.append("OBJECT_IS_MASTER")
    if value & 0x02:
        flags.append("OBJECT_REPLICABLE")
    if value & 0x04:
        flags.append("OBJECT_WRITEABLE")

    return "|".join(flags) if flags else "NONE"


def ldap_search(conn, base_domain, query, attributes=None):

    result_list = []
    for entry in conn.extend.standard.paged_search(
                                                    search_base=base_domain,
                                                    search_filter=query,
                                                    search_scope=SUBTREE,
                                                    attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES] if not attributes else attributes,
                                                    paged_size=1000,
                                                    generator=True):
        if entry.get('type') == 'searchResEntry':
            dn = entry.get('dn')
            attrs = entry.get('attributes', {})
            new_entry = {"name": dn, "attrs": []}
            
            for k, v in attrs.items():
                if k=="userAccountControl":
                    new_entry["attrs"].append({"id": k, "val": decode_uac(v)})
                elif k=="instanceType":

                    new_entry["attrs"].append({"id": k, "val": decode_instance_type(v)})
                else:    
                    new_entry["attrs"].append({"id": k, "val": v})
            result_list.append(new_entry)            
    return result_list

def main():
    examples = r"""
    Examples:

    # normal dump 
    python ldap-enum.py -i 10.10.10.10 -u 'domain\user1' -p 'pwd' -d 'htb.domain'

    # ssl dump 
    python ldap-enum.py -i 10.10.10.10 -u 'domain\user1' -p 'pwd' -d 'htb.domain' --use-ssl

    # auto resolve domain 
    python ldap-enum.py -i 10.10.10.10 -u 'domain\user1' -p 'pwd' -d auto

    """
    parser = argparse.ArgumentParser(
        description="LDAP dumper tool",
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ip", "-i",required=True, type=str, help="Remote IP")
    parser.add_argument("--user", "-u",required=False, type=str, help="Username")
    parser.add_argument("--pwd", "-p", required=False, type=str, help="Password")
    parser.add_argument("--domain", "-d", required=True, type=str, help="DC Domain ex: puppy.htb")
    parser.add_argument("--use-ssl", required=False, action="store_true", help="Use LDAPS (SSL) on the connection")
    


    args = parser.parse_args()
    

    
    tls_config =Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    if not args.use_ssl:
        server = Server(f"ldap://{args.ip}", get_info=ALL)
    else:
        server = Server(f"ldaps://{args.ip}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)

    conn = Connection(server, user=args.user, password=args.pwd, auto_bind=True)

    if args.domain.lower() == "auto":
        print("[*] Resolving base domain via RootDSE...")
        conn.search(search_base='', search_filter='(objectClass=*)', search_scope=BASE, attributes=['defaultNamingContext'])
        if conn.entries:
            base_domain = conn.entries[0].defaultNamingContext.value
            print(f"[+] Base domain resolved: {base_domain}")
        else:
            print("[-] Could not resolve base domain automatically.")
            sys.exit(1)
    else:
        base_domain=args.domain.replace(".",",DC=")
        base_domain="DC="+base_domain
    
    print("[*] Getting users info...")
    users_full = ldap_search(conn, base_domain, '(sAMAccountName=*)')

    rendered_html = template.render(generated_on=datetime.now().strftime("%Y-%m-%d %H:%M"),
                                    users_full = users_full
                                    )

    with open('full_accounts.html', 'w', encoding='utf-8') as f:
        f.write(rendered_html)


    conn.unbind()
if __name__ == "__main__":
    main()


