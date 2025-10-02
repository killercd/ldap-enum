#!/usr/bin/python
import subprocess
import argparse
import sys
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES

env = Environment(loader=FileSystemLoader('r_templates'))
template = env.get_template('full_accounts.html')


def safe_decode(val):
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8')
        except UnicodeDecodeError:
            return val.decode('latin-1', errors='replace')
    else:
        return str(val)


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
                new_entry["attrs"].append({"id": k, "val": ", ".join(safe_decode(x) for x in v)})
            result_list.append(new_entry)            
    return result_list

def main():
    parser = argparse.ArgumentParser(description="LDAP dumper tool tool")
    parser.add_argument("--ip", "-i",required=True, type=str, help="Remote IP")
    parser.add_argument("--user", "-u",required=False, type=str, help="Username")
    parser.add_argument("--pwd", "-p", required=False, type=str, help="Password")
    parser.add_argument("--domain", "-d", required=True, type=str, help="DC Domain ex: puppy.htb")
    parser.add_argument("--row-format", action="store_true", help="Display in rows")
    


    args = parser.parse_args()
    print("[*] Querying users...")

    

    base_domain=args.domain.replace(".",",DC=")
    base_domain="DC="+base_domain
    

    server = Server(f"ldap://{args.ip}", get_info=ALL)
    conn = Connection(server, user=args.user, password=args.pwd, auto_bind=True)
   
    users_full = ldap_search(conn, base_domain, '(sAMAccountName=*)')

    rendered_html = template.render(generated_on=datetime.now().strftime("%Y-%m-%d %H:%M"),
                                    users_full = users_full
                                    )

    with open('full_accounts.html', 'w', encoding='utf-8') as f:
        f.write(rendered_html)


    conn.unbind()
if __name__ == "__main__":
    main()