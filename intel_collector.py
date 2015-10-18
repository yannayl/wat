"""
Most of the code copied from wifite (https://github.com/derv82/wifite)
"""
import csv
import os
import re
import subprocess
import time
import tempfile
import glob
import argparse
import sys

class Target:
    """
        Holds data for a Target (aka Access Point aka Router)
    """
    def __init__(self, bssid, power, data, channel, encryption, ssid):
        self.bssid = bssid
        self.power = power
        self.data = data
        self.channel = channel
        self.encryption = encryption
        self.ssid = ssid
        self.wps = False  # Default to non-WPS-enabled router.
        self.key = ''


class Client:
    """
        Holds data for a Client (device connected to Access Point/Router)
    """
    def __init__(self, bssid, station, power):
        self.bssid = bssid
        self.station = station
        self.power = power


class IntelCollector(object):
    def __init__(self, iface):
        self._prefix = tempfile.mktemp("wat")
        self._iface = iface
        self.targets = None
        self.clients = None
        self._interval = 5
        self._cmd = ["airodump-ng",
                     "-w", self._prefix,
                     "--output-format", "csv",
                     "--encrypt", "WPA",
                     self._iface]

    def __del__(self):
        for f in glob.glob(self._prefix + "*"):
            os.remove(f)

    def parse_csv(self):
        """
            Parses given lines from airodump-ng CSV file.
            Returns tuple: List of targets and list of clients.
        """
        filename = self._prefix + "-01.csv"
        if not os.path.exists(filename): return ([], [])
        targets = []
        clients = []
        try:
            hit_clients = False
            with open(filename, 'rb') as csvfile:
                targetreader = csv.reader((line.replace('\0', '') for line in csvfile), delimiter=',')
                for row in targetreader:
                    if len(row) < 2:
                        continue
                    if not hit_clients:
                        if row[0].strip() == 'Station MAC':
                            hit_clients = True
                            continue
                        if len(row) < 14:
                            continue
                        if row[0].strip() == 'BSSID':
                            continue
                        enc = row[5].strip()
                        wps = False
                        # Ignore non-WPA and non-WEP encryption
                        if enc.find('WPA2') != -1: continue
                        if enc == "WPA2WPA" or enc == "WPA2 WPA":
                            enc = "WPA2"
                            wps = True
                        if len(enc) > 4:
                            enc = enc[4:].strip()
                        power = int(row[8].strip())

                        ssid = row[13].strip()
                        ssidlen = int(row[12].strip())
                        ssid = ssid[:ssidlen]

                        if power < 0: power += 100
                        t = Target(row[0].strip(), power, row[10].strip(), row[3].strip(), enc, ssid)
                        t.wps = wps
                        targets.append(t)
                    else:
                        if len(row) < 6:
                            continue
                        bssid = re.sub(r'[^a-zA-Z0-9:]', '', row[0].strip())
                        station = re.sub(r'[^a-zA-Z0-9:]', '', row[5].strip())
                        power = row[3].strip()
                        if station != 'notassociated':
                            c = Client(bssid, station, power)
                            clients.append(c)
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)
            return ([], [])

        return (targets, clients)

    def start(self):
        airodump = subprocess.Popen(self._cmd, stdout=open(os.devnull, 'w'), stderr=subprocess.STDOUT)

        while not airodump.poll():
            (self.targets, self.clients) = self.parse_csv()
            print map(str, self.targets)
            print map(str, self.clients)
            time.sleep(self._interval)

    def choose_target(self):
        """
        :return: waits till a target is chosen
        """
        pass


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("iface", type=str)
    parsed = parser.parse_args(args[1:])

    IntelCollector(parsed.iface).start()

if __name__ == "__main__":
    sys.exit(main(sys.argv))