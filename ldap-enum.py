#!/usr/bin/python
import subprocess
import argparse
import sys

def print_c(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "reset": "\033[0m"
    }

    if color not in colors:
        color = "reset"
    print(f"{colors[color]}{text}{colors['reset']}")


def ldap_query(ip, 
                ad_username, 
                pwd, 
                base_domain,
                query, 
                params):

    return  subprocess.run(["ldapsearch", 
                             "-H", 
                             f"ldap://{ip}", 
                             "-D"
                             f"{ad_username}",
                             "-w",
                             f"{pwd}",
                             "-b",
                             f"{base_domain}",
                            f"{query}",
                            f"{params}"], 
                            capture_output=True, text=True)

def filter_rows(rows, filter):
   rows = rows.split("\n")
   for el in rows:
       if el.find(filter)>=0: yield el

def separator(row):
    return ", " if not row else "\n"

def main():
    parser = argparse.ArgumentParser(description="LDAP enumeration tool")
    parser.add_argument("--ip", "-i",required=True, type=str, help="Remote IP")
    parser.add_argument("--user", "-u",required=False, type=str, help="Username")
    parser.add_argument("--pwd", "-p", required=False, type=str, help="Password")
    parser.add_argument("--domain", "-d", required=True, type=str, help="DC Domain ex: puppy.htb")
    parser.add_argument("--row-format", action="store_true", help="Display in rows")
    


    args = parser.parse_args()
    print("[*] Querying users...")

    ad_username=f"{args.user}@{args.domain}"
    base_domain=args.domain.replace(".",",DC=")
    base_domain="DC="+base_domain
    
    result = ldap_query(args.ip, 
                        ad_username, 
                        args.pwd, 
                        base_domain,
                        "(&(objectCategory=person)(objectClass=user))",
                        "sAMAccountName")
    
    if result.stderr:
        print_c(result.stderr,"red")
        sys.exit(1)

    filtered_users = filter_rows(result.stdout, "sAMAccountName:")
    users  = list(map(lambda x: x.replace("sAMAccountName: ",""), filtered_users))


    print_c(separator(args.row_format).join(users),"green")
    print("")
    print("[*] Querying groups...")
    
    result = ldap_query(args.ip, 
                        ad_username, 
                        args.pwd, 
                        base_domain,
                        "(objectClass=group)",
                        "cn")    
    if result.stderr:
        print_c(result.stderr,"red")
        sys.exit(1)

    filtered_groups = filter_rows(result.stdout, "cn:")
    groups  = list(map(lambda x: x.replace("cn: ",""), filtered_groups))
    print_c(separator(args.row_format).join(groups),"green")
    print("")

    print("[*] Querying members of groups...")
    for group in groups:
        result = ldap_query(args.ip, 
                            ad_username, 
                            args.pwd, 
                            base_domain,
                            f"(cn={group})",
                            "member")
        
        if result.stderr:
            print_c(result.stderr,"red")
            sys.exit(1)

        filtered_user_in_group = filter_rows(result.stdout, "member:")
        print("")
        print(f"Group {group}:")
        for fuser in filtered_user_in_group:
            fuser = fuser.split("member: ")[1
                                            ]
            result_usr = ldap_query(args.ip, 
                            ad_username, 
                            args.pwd, 
                            fuser,
                            "(objectClass=*)",
                            "sAMAccountName")
            
            if result_usr.stderr:
                print_c(result_usr.stderr,"red")
                sys.exit(1)

            
            filtered_real_usr = filter_rows(result_usr.stdout, "sAMAccountName:")
            user_extr  = list(map(lambda x: x.replace("sAMAccountName: ",""), filtered_real_usr))
            if user_extr:
                print_c(user_extr[0],"green")
            



        # print_c(separator(args.row_format).join(users_extr),"green")
        # print("")




if __name__ == "__main__":
    main()