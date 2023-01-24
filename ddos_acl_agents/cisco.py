"""
Функции для управления IP через ssh expect ios
"""
import re
import pexpect


def cisco_start_session(router, login, password, attempts=3):
    """

    :param router: router IP-address
    :param login: login information (ssh)
    :param password: password(ssh)
    :param attempts: number of attempts to login

    """
    global cisco
    print(router+"(cisco): connecting...")
    cisco = pexpect.spawn('ssh '+login+'@'+router, encoding='utf-8')
    ssh_newkey = 'Are you sure you want to continue connecting'
    for i in range(attempts):
        try:
            i = cisco.expect([pexpect.TIMEOUT, ssh_newkey, '[Pp]assword:'])
            if i == 1:  # SSH does not have the public key. Just accept it.
                cisco.sendline('yes')
                cisco.expect('[Pp]assword:')
            cisco.sendline(password)
            cisco.expect(r'#')
            result = True
            break
        except:
            result = False
    return result


def cisco_check_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    cisco.sendline('sh ip prefix-list stop-ddos\r')
    cisco.expect(r'#')
    output = cisco.before
    if re.search(subnet, output):
        print(router+"(cisco): "+subnet+" exists in ACL")
    else:
        print(router+"(cisco): "+subnet+" not exists in ACL")


def cisco_add_net_to_ddos_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    cisco.sendline('conf t\r')
    cisco.expect(r'\(config\)#')
    print(router+"(cisco): adding "+subnet+" to ACL...")
    cisco.sendline('ip prefix-list stop-ddos permit '+subnet+' le 32\r')
    cisco.expect(r'\(config\)#')
    cisco.sendline('exit\r')
    cisco.expect(r'#')


def cisco_remove_net_from_ddos_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    cisco.sendline('conf t\r')
    cisco.expect(r'\(config\)#')
    print(router+"(cisco): removing "+subnet+" from ACL...")
    cisco.sendline('no ip prefix-list stop-ddos permit '+subnet+' le 32\r')
    cisco.expect(r'\(config\)#')
    cisco.sendline('exit\r')
    cisco.expect(r'#')


def cisco_block_ip_for_ddos(ip, router):
    """

    :param ip: client ip for ddos_guard blackhole
    :param router: router IP-address

    """
    cisco.sendline('conf t\r')
    cisco.expect(r'\(config\)#')
    print(router+"(cisco): blackholing "+ip+"...")
    cisco.sendline('ip route '+ip+' 255.255.255.255 Null 0 tag 666\r')
    cisco.expect(r'\(config\)#')
    cisco.sendline('exit\r')
    cisco.expect(r'#')


def cisco_unblock_ip_for_ddos(ip, router):
    """

    :param ip: client ip for ddos_guard blackhole
    :param router: router IP-address

    """
    cisco.sendline('conf t\r')
    cisco.expect(r'\(config\)#')
    print(router+"(cisco): unblocking "+ip+"...")
    cisco.sendline('no ip route '+ip+' 255.255.255.255 Null 0 tag 666\r')
    cisco.expect(r'\(config\)#')
    cisco.sendline('exit\r')
    cisco.expect(r'#')


def cisco_logout():
    """ Cisco logout """
    cisco.close()
