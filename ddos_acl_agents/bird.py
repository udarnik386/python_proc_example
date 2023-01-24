"""
Функции для управления IP через BIRD
"""
import re
import os
from urllib.parse import urlencode
import pycurl
from common.main import error_message


def bird_remote(router, login, password, client_ip, action):
    """

    :param router: jenkins IP-address
    :param login: login information (jenkins)
    :param password: password (jenkins)
    :param client_ip: client IP-address (IP/Subnet)
    :param action: main action (IPblackhole_block, IPblackhole_release)

    """
    print(router+"(bird): trying "+action+" "+client_ip+" ...")
    url = "https://"+router+"/job/conf_bird_ip_auto_ddos.dsl/buildWithParameters"
    post_data = {action: client_ip}
    postfields = urlencode(post_data)
    bird_remote = pycurl.Curl()
    bird_remote.setopt(pycurl.POST, 1)
    bird_remote.setopt(pycurl.POSTFIELDS, postfields)
    bird_remote.setopt(pycurl.URL, url)
    bird_remote.setopt(pycurl.HTTPHEADER, [
        'Accept: application/json',
        'X-Requested-By:ddos_acl_controller'])
    bird_remote.setopt(pycurl.VERBOSE, 0)
    bird_remote.setopt(pycurl.CONNECTTIMEOUT, 5)
    bird_remote.setopt(pycurl.SSL_VERIFYPEER, 0)
    bird_remote.setopt(pycurl.SSL_VERIFYHOST, 0)
    bird_remote.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
    bird_remote.setopt(pycurl.USERPWD, "%s:%s" % (login, password))
    bird_remote.perform()
    bird_remote.close()


def bird_local_check(bird_config, client_ip):
    """

    :param bird_config: path to BIRD config (local)
    :param client_ip: client IP-address (IP/Subnet)

    """
    if os.stat(bird_config).st_size == 0:
        return "local(bird): "+client_ip+" not exists in ACL"
    with open(bird_config, "r") as bird_local:
        lines = bird_local.readlines()
        for line in lines:
            if re.search(client_ip, line):
                return "local(bird): "+client_ip+" exists in ACL"
    return "local(bird): "+client_ip+" not exists in ACL"


def bird_local_block(bird_config, client_ip):
    """

    :param bird_config: path to BIRD config (local)
    :param client_ip: client IP-address (IP/Subnet)

    """
    print("local(bird): adding "+client_ip+" to bird config "+bird_config+" ...")
    with open(bird_config, "r") as bird_local:
        lines = bird_local.readlines()
    for line in lines:
        if re.search(client_ip, line):
            error_message("local(bird): "+client_ip+" already exists in ACL")
    with open(bird_config, "a") as bird_local:
        bird_local.write("route "+client_ip+" reject;")
        bird_local.close()


def bird_local_unblock(bird_config, client_ip):
    """

    :param bird_config: path to BIRD config (local)
    :param client_ip: client IP-address (IP/Subnet)

    """
    print("local(bird): removing "+client_ip+" from bird config "+bird_config+" ...")
    with open(bird_config, "r") as bird_local:
        lines = bird_local.readlines()
    with open(bird_config, "w") as bird_local:
        for line in lines:
            if line.strip("\n") != "route "+client_ip+" reject;":
                bird_local.write(line)
