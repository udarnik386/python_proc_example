"""
Функции для управления IP через ssh expect brocade
"""
import re
import pexpect


def brocade_start_session(router, login, password, attempts=3):
    """

    :param router: router IP-address
    :param login: login information (ssh)
    :param password: password(ssh)
    :param attempts: number of attempts to login

    """
    global brocade
    print(router+"(brocade): connecting...")
    brocade = pexpect.spawn('ssh '+login+'@'+router, encoding='utf-8')
    ssh_newkey = 'Are you sure you want to continue connecting'
    for i in range(attempts):
        try:
            i = brocade.expect([pexpect.TIMEOUT, ssh_newkey, '[Pp]assword:'])
            if i == 1:  # SSH does not have the public key. Just accept it.
                brocade.sendline('yes')
                brocade.expect('[Pp]assword:')
            brocade.sendline(password)
            brocade.expect(r'#')
            result = True
            break
        except:
            result = False
    return result


def brocade_check_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    brocade.sendline('sh ip prefix-lists stop-ddos\r')
    brocade.expect(r'#')
    output = brocade.before
    if re.search(subnet, output):
        print(router+"(brocade): "+subnet+" exists in ACL")
    else:
        print(router+"(brocade): "+subnet+" not exists in ACL")


def brocade_add_net_to_ddos_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    brocade.sendline('conf t\r')
    brocade.expect(r'\(config\)#')
    print(router+"(brocade): adding "+subnet+" to ACL...")
    brocade.sendline('ip prefix-list stop-ddos permit '+subnet+' le 32\r')
    brocade.expect(r'\(config\)#')
    brocade.sendline('exit\r')
    brocade.expect(r'#')


def brocade_remove_net_from_ddos_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    brocade.sendline('conf t\r')
    brocade.expect(r'\(config\)#')
    print(router+"(brocade): removing "+subnet+" from ACL...")
    brocade.sendline('no ip prefix-list stop-ddos permit '+subnet+' le 32\r')
    brocade.expect(r'\(config\)#')
    brocade.sendline('exit\r')
    brocade.expect(r'#')


def brocade_block_ip_for_ddos(ip, router):
    """

    :param ip: client ip for ddos_guard blackhole
    :param router: router IP-address

    """
    brocade.sendline('conf t\r')
    brocade.expect(r'\(config\)#')
    print(router+"(brocade): blackholing "+ip+"...")
    brocade.sendline('ip route '+ip+' Null0 tag 666\r')
    brocade.expect(r'\(config\)#')
    brocade.sendline('exit\r')
    brocade.expect(r'#')


def brocade_unblock_ip_for_ddos(ip, router):
    """

    :param ip: client ip for ddos_guard blackhole
    :param router: router IP-address

    """
    brocade.sendline('conf t\r')
    brocade.expect(r'\(config\)#')
    print(router+"(brocade): unblocking "+ip+"...")
    brocade.sendline('no ip route '+ip+' Null0 tag 666\r')
    brocade.expect(r'\(config\)#')
    brocade.sendline('exit\r')
    brocade.expect(r'#')


def brocade_logout():
    """ Brocade logout """
    brocade.close()
