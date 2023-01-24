"""
Общие функции, парсинг конфигурации, опций, обработка ошибок
"""
import sys
import getopt
import ipaddress
import textwrap
import yaml


def usage():
    """ Script usage """
    message = """
              -h --help      print this message
              -c --config    configuration file
              -r --router    router ip address and platform in notation: platform@ip
              -s --subnet    subnet (you can`t use it with client_ip param)
              -i --client_ip ip address (you can`t use it with subnet param
              -a --action    main action:
              \t\t| block - block subnet/client_ip
              \t\t| unblock - unblock subnet/client_ip
              \t\t| check - check block/unblock status
              """
    result = textwrap.dedent(message)
    print("Usage: "+sys.argv[0]+" [option] argument")
    print(result)


def error_message(message="Owls are not what they seem!", send_message = False):
    """

    :param message:  (Default value = "Owls are not what they seem!")
    :param send_message: if true send message to kayako host

    """
    print(message)
    if send_message:
        print("send message to kayako")
    sys.exit(1)


def arg_check_exists(opt, arg):
    """

    :param opt: script option
    :param arg: option argument

    """
    if arg is None:
        error_message("Option "+opt+" requires an argument")
    return arg


def get_options():
    """Function parce incomming options"""
    default_config = "config.yml"
    routers = []
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hr:c:s:i:a:",
                                   ["help",
                                    "router=",
                                    "config=",
                                    "subnet=",
                                    "client_ip=",
                                    "action="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-r", "--router"):
            if arg is not None:
                routers.append(arg)
            else:
                error_message("Option "+opt+" requires an argument")
        elif opt in ("-c", "--config"):
            try:
                configfile
                error_message("Requires only one "+opt+" argument")
            except NameError:
                configfile = arg_check_exists(opt, arg)
        elif opt in ("-s", "--subnet"):
            try:
                subnet
                error_message("Requires only one "+opt+" argument")
            except NameError:
                try:
                    client_ip
                    error_message("You must use only one param: subnet or ip, not both")
                except NameError:
                    subnet = arg_check_exists(opt, arg)
        elif opt in ("-i", "--client_ip"):
            try:
                client_ip
                error_message("Requires only one "+opt+" argument")
            except NameError:
                try:
                    subnet
                    error_message("You must use only one param: subnet or ip, not both")
                except NameError:
                    client_ip = arg_check_exists(opt, arg)
        elif opt in ("-a", "--action"):
            try:
                action
                error_message("Requires only one "+opt+" argument")
            except NameError:
                action = arg_check_exists(opt, arg)
                if action not in ("block", "unblock", "check"):
                    error_message("Wrong "+opt+" argument "+arg+", possible args: block, unblock, check")
        else:
            usage()
            sys.exit()
    try:
        configfile
    except NameError:
        configfile = default_config
    try:
        valided_subnet = ipaddress.ip_network(subnet).with_prefixlen
    except NameError:
        valided_subnet = None
    except ValueError:
        error_message("Wrong subnet address: "+subnet)
    try:
        valided_ip = ipaddress.ip_network(client_ip).with_prefixlen
        if int(ipaddress.ip_network(client_ip).prefixlen) != int(32):
            error_message("Wrong ip address: "+ip)
    except NameError:
        valided_ip = None
    except ValueError:
        error_message("Wrong ip address: "+client_ip)
    try:
        options = {"configfile": configfile,
                   "subnet": valided_subnet,
                   "ip": valided_ip,
                   "routers": routers,
                   "action": action}
    except UnboundLocalError as err:
        print(err)
        error_message("There are no required argument")
    return options


def router_param_parcer(router_option):
    router_dict = {}
    router_list = router_option.split('@')
    router_ip = router_list.pop()
    router_platform = router_list.pop()
    router_dict["ip"] = router_ip
    router_dict["platform"] = router_platform
    return router_dict


def get_config(configfile="config.yml"):
    """

    :param configfile:  (Default value = "config.yml")

    """
    try:
        configfile
        open(configfile)
    except IOError as err:
        if configfile == "config.yml":
            try:
                configfile = "/etc/hkphpflow/ddos_acl_controller.yml"
                open(configfile)
            except IOError:
                print(err)
                error_message("Configuration not found")
        else:
            print(err)
            error_message("Configuration not found")
    stream = open(configfile, 'r')
    conf = yaml.load(stream)
    return conf


def get_conf_by_router(router, configfile):
    """

    Function parce main configuration file
    :param router: router IP address
    :param configfile: main script configuration file path

    """
    conf = get_config(configfile)
    for location in conf.get("locations"):
        for ips in conf.get("locations").get(location).get("routers"):
            if ips.get("ip") == router:
                router_conf = {"location": location, "router": router}
                if ips.get("owner") is not None:
                    owner = ips.get("owner")
                    router_conf.update({"owner": owner})
                else:
                    error_message("there are no owner for "+router+" in "+configfile)
                if ips.get("bird_config") is not None:
                    router_conf.update({"bird_config": ips.get("bird_config")})
                elif conf.get("creds").get(owner) is not None:
                    router_conf.update({"bird_config": conf.get("creds").get(owner).get("bird_config")})
                else:
                    router_conf.update({"bird_config": None})
                if ips.get("login") is not None:
                    router_conf.update({"login": ips.get("login")})
                elif conf.get("creds").get(owner) is not None:
                    router_conf.update({"login": conf.get("creds").get(owner).get("login")})
                else:
                    error_message("there are no login in "+configfile)
                if ips.get("pass") is not None:
                    router_conf.update({"password": ips.get("pass")})
                elif conf.get("creds").get(owner) is not None:
                    router_conf.update({"password": conf.get("creds").get(owner).get("pass")})
                else:
                    error_message("there are no password in "+configfile)
                break
    return router_conf
