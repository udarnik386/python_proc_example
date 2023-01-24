"""
Функции для управления IP через ssh expect brocade
"""
import re
import pexpect


def juniper_start_session(router, login, password, attempts=3):
    """

    :param router: router IP-address
    :param login: login information (ssh)
    :param password: password(ssh)
    :param attempts: number of attempts to login

    """
    global juniper
    print(router+"(juniper): connecting...")
    juniper = pexpect.spawn('ssh '+login+'@'+router,
                            encoding='utf-8',
                            timeout=100)
    ssh_newkey = 'Are you sure you want to continue connecting'
    for i in range(attempts):
        try:
            i = juniper.expect([pexpect.TIMEOUT, ssh_newkey, '[Pp]assword:'])
            if i == 1:  # SSH does not have the public key. Just accept it.
                juniper.sendline('yes')
                juniper.expect('[Pp]assword:')
            juniper.sendline(password)
            juniper.expect(r'> $')
            result = True
            break
        except:
            result = False
    return result


def juniper_check_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    juniper.sendline('show configuration policy-options prefix-list stop-ddos')
    juniper.expect(r'> $')
    output = juniper.before
    if re.search(subnet, output):
        print(router+"(juniper): "+subnet+" exists in ACL")
    else:
        print(router+"(juniper): "+subnet+" not exists in ACL")


def juniper_add_net_to_ddos_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    juniper.sendline('config\r')
    juniper.expect(r'# $')
    print(router+"(juniper): adding "+subnet+" to ACL...")
    juniper.sendline('set policy-options prefix-list stop-ddos '+subnet+'\r')
    juniper.expect(r'# $')
    juniper.sendline('commit and-quit\r')
    juniper.expect(r'> $')


def juniper_remove_net_from_ddos_acl(subnet, router):
    """

    :param subnet: client subnet for ddos_guard
    :param router: router IP-address

    """
    juniper.sendline('config\r')
    juniper.expect(r'# $')
    print(router+"(juniper): removing "+subnet+" from ACL...")
    juniper.sendline('delete policy-options prefix-list stop-ddos '+subnet+'\r')
    juniper.expect(r'# $')
    juniper.sendline('commit and-quit\r')
    juniper.expect(r'> $')


def juniper_block_ip_for_ddos(ip, router):
    """

    :param ip: client ip for ddos_guard blackhole
    :param router: router IP-address

    """
    juniper.sendline('config\r')
    juniper.expect(r'# $')
    print(router+"(juniper): blackholing "+ip+"...")
    juniper.sendline('set routing-options static route '+ip+'/32 discard tag 666\r')
    juniper.expect(r'# $')
    juniper.sendline('commit and-quit\r')
    juniper.expect(r'> $')


def juniper_unblock_ip_for_ddos(ip, router):
    """

    :param ip: client ip for ddos_guard blackhole
    :param router: router IP-address

    """
    juniper.sendline('config\r')
    juniper.expect(r'# $')
    print(router+"(juniper): unblocking "+ip+"...")
    juniper.sendline('delete routing-options static route '+ip+'/32\r')
    juniper.expect(r'# $')
    juniper.sendline('commit and-quit\r')
    juniper.expect(r'> $')


def juniper_logout():
    """ Juniper logout"""
    juniper.close()
