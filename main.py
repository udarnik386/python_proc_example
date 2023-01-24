#!/usr/bin/env python3
"""
Скрипт, на основе параметров и конфигурационного файла (описаны в common/main.py),
управляет переводом подсетей под DDoS-защиту и вывода из под нее.
Также, если входным параметром является IP-адрес, может заблокировать его локально
(BIRD), через jenkins (ip указывается на месте router), или через роутер.
"""
from ddos_acl_agents.brocade import (
    brocade_start_session,
    brocade_check_acl,
    brocade_add_net_to_ddos_acl,
    brocade_remove_net_from_ddos_acl,
    brocade_block_ip_for_ddos,
    brocade_unblock_ip_for_ddos,
    brocade_logout)
from ddos_acl_agents.cisco import (
    cisco_start_session,
    cisco_check_acl,
    cisco_add_net_to_ddos_acl,
    cisco_remove_net_from_ddos_acl,
    cisco_block_ip_for_ddos,
    cisco_unblock_ip_for_ddos,
    cisco_logout)
from ddos_acl_agents.juniper import (
    juniper_start_session,
    juniper_check_acl,
    juniper_add_net_to_ddos_acl,
    juniper_remove_net_from_ddos_acl,
    juniper_block_ip_for_ddos,
    juniper_unblock_ip_for_ddos,
    juniper_logout)
from ddos_acl_agents.bird import (
    bird_remote,
    bird_local_check,
    bird_local_block,
    bird_local_unblock)
from common.main import error_message, get_options, get_conf_by_router, router_param_parcer
from multiprocessing import Process


def processing_router(configfile, platform, action, subnet, client_ip, router_ip):
    main_conf = []
    result = False
    try:
        main_conf.append(get_conf_by_router(router_ip, configfile))
    except:
        error_message("Wrong router ip "+router_ip+" or router not in configuration file")
    if subnet is not None:
        for router_conf in main_conf:
            router_conf.update({"subnet": subnet, "platform": platform})
            router = router_conf["router"]
            login = router_conf["login"]
            password = router_conf["password"]
        if platform == "brocade":
            start_session_result = brocade_start_session(router, login, password)
            if not start_session_result:
                error_message("Ssh session for router "+router_ip+" was not started", send_message=True)
            if action == "block":
                brocade_add_net_to_ddos_acl(subnet, router)
            elif action == "unblock":
                brocade_remove_net_from_ddos_acl(subnet, router)
            elif action == "check":
                brocade_check_acl(subnet, router)
            brocade_logout()
            result = True
        elif platform == "cisco":
            start_session_result = cisco_start_session(router, login, password)
            if not start_session_result:
                error_message("Ssh session for router "+router_ip+" was not started", send_message=True)
            if action == "block":
                cisco_add_net_to_ddos_acl(subnet, router)
            elif action == "unblock":
                cisco_remove_net_from_ddos_acl(subnet, router)
            elif action == "check":
                cisco_check_acl(subnet, router)
            cisco_logout()
            result = True
        elif platform == "juniper":
            start_session_result = juniper_start_session(router, login, password)
            if not start_session_result:
                error_message("Ssh session for router "+router_ip+" was not started", send_message=True)
            if action == "block":
                juniper_add_net_to_ddos_acl(subnet, router)
            elif action == "unblock":
                juniper_remove_net_from_ddos_acl(subnet, router)
            elif action == "check":
                juniper_check_acl(subnet, router)
            juniper_logout()
            result = True
        else:
            error_message("Platform "+platform+" not supported")
    elif client_ip is not None:
        for router_conf in main_conf:
            router_conf.update({"ip": client_ip, "platform": platform})
            router = router_conf["router"]
            login = router_conf["login"]
            password = router_conf["password"]
            if platform == "brocade":
                start_session_result = brocade_start_session(router, login, password)
                if not start_session_result:
                    error_message("Ssh session for router "+router_ip+" was not started", send_message=True)
                if action == "block":
                    brocade_block_ip_for_ddos(client_ip, router)
                if action == "unblock":
                    brocade_unblock_ip_for_ddos(client_ip, router)
                elif action == "check":
                    print("there are no method check for ip")
                brocade_logout()
                result = True
            elif platform == "cisco":
                start_session_result = cisco_start_session(router, login, password)
                if not start_session_result:
                    error_message("Ssh session for router "+router_ip+" was not started", send_message=True)
                if action == "block":
                    cisco_block_ip_for_ddos(client_ip, router)
                if action == "unblock":
                    cisco_unblock_ip_for_ddos(client_ip, router)
                elif action == "check":
                    print("there are no method check for ip")
                cisco_logout()
                result = True
            elif platform == "juniper":
                start_session_result = juniper_start_session(router, login, password)
                if not start_session_result:
                    error_message("Ssh session for router "+router_ip+" was not started", send_message=True)
                if action == "block":
                    juniper_block_ip_for_ddos(client_ip, router)
                if action == "unblock":
                    juniper_unblock_ip_for_ddos(client_ip, router)
                elif action == "check":
                    print("there are no method check for ip")
                juniper_logout()
                result = True
            elif platform == "bird":
                bird_config = router_conf["bird_config"]
                if bird_config is None:
                    error_message("There are no bird_config in config file")
                if action == "block" and router == "127.0.0.1":
                    bird_local_block(bird_config, client_ip)
                    result = True
                elif action == "unblock" and router == "127.0.0.1":
                    bird_local_unblock(bird_config, client_ip)
                    result = True
                elif action == "block" and router != "127.0.0.1":
                    bird_remote(
                        router,
                        login,
                        password,
                        client_ip,
                        "IPblackhole_block")
                    result = True
                elif action == "unblock" and router != "127.0.0.1":
                    bird_remote(
                        router,
                        login,
                        password,
                        client_ip,
                        "IPblackhole_release")
                    result = True
                elif action == "check":
                    print(bird_local_check(bird_config, client_ip))
            else:
                error_message("Platform "+platform+" not supported")
    return result


def main():
    """Main function"""
    options = get_options()
    procs = []
    for router in options["routers"]:
        router_dict = router_param_parcer(router)
        proc = Process(target=processing_router, args=(
            options["configfile"],
            router_dict["platform"],
            options["action"],
            options["subnet"],
            options["ip"],
            router_dict["ip"]))
        procs.append(proc)
        proc.start()
    for proc in procs:
        proc.join()


if __name__ == "__main__":
    main()
