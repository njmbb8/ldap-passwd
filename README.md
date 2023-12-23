
# LDAP Remote Password Changer

This script is an implementation of a technique found in https://trustedsec.com/blog/manipulating-user-passwords-without-mimikatz. Recently on a CTF I ran into almost the same situation described in the article but I was unable to get it to work due to only having GenericWrite, not ForceChangePassword. While this was a learning moment for me, I decided to build out the script in case anyone else(or myself) runs into a situation where they have LDAP access to an account with ForceChangePassword over another account.


## Usage/Examples

```bash
python ldap-passwd.py -t example.com -u User.Name -p 'Password123!' -c hazel.green -n 'P@55w0rd' -d 'example.com' -s 
```

