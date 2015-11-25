"""
Most of the code copied from wifite (https://github.com/derv82/wifite)
"""
import csv
import os
import re
import subprocess
import tempfile
import glob
import argparse
import sys
import time
import common
import logging
import shutil


class IntelCollector(object):
    def __init__(self, iface, save_dir=None):
        self._prefix = tempfile.mktemp("wat")
        self._iface = iface
        self.targets = None
        self.clients = None
        self._interval = 5
        self._cmd = ["airodump-ng",
                     "-w", self._prefix,
                     "--output-format", "csv",
                     "--encrypt", "WPA2",
                     self._iface]
        self._proc_airodump = None
        self._save_dir = save_dir

    def __del__(self):
        for f in glob.glob(self._prefix + "*"):
            os.remove(f)

    def _parse_csv_ap(self, row):
        if len(row) < 14:
            return None
        if row[0].strip() == 'BSSID':
            return None
        enc = row[5].strip()
        wps = False
        # Ignore non-WPA and non-WEP encryption
        if enc.find('WPA2') == -1:
            return None
        if enc == "WPA2WPA" or enc == "WPA2 WPA":
            enc = "WPA2"
            wps = True
        if len(enc) > 4:
            enc = enc[4:].strip()
        power = int(row[8].strip())

        ssid = row[13].strip()
        ssidlen = int(row[12].strip())
        ssid = ssid[:ssidlen]

        if power < 0:
            power += 100
        a = common.AccessPoint(row[0].strip(), power, row[10].strip(),
                               int(row[3].strip()), enc, ssid)
        a.wps = wps
        return a

    def _parse_csv_client(self, row):
        if len(row) < 6:
            return None

        station = re.sub(r'[^a-zA-Z0-9:]', '', row[5].strip())
        if station == 'notassociated':
            return None

        bssid = re.sub(r'[^a-zA-Z0-9:]', '', row[0].strip())
        power = int(row[3].strip())
        if power == -1:
            power = -1000000
        return common.Client(bssid, station, power)

    def _get_csvfiles(self):
        files = glob.glob(self._prefix + "-*.csv")
        if not file:
            return None

        return files

    def _parse_csvs(self):
        """
            Parses given lines from airodump-ng CSV file.
            Returns tuple: List of targets and list of clients.
        """
        filenames = self._get_csvfiles()
        if not filenames:
            return ([], [])

        aps = []
        clients = []
        for filename in filenames:
            temp_aps, temp_clients = self._parse_csv(filename)
            aps.extend(temp_aps)
            clients.extend(temp_clients)

        return aps, clients

    def _parse_csv(self, filename):
        aps = []
        clients = []
        hit_clients = False
        try:
            with open(filename, 'rb') as csvfile:
                targetreader = csv.reader(
                    (line.replace('\0', '') for line in csvfile), delimiter=',')
                for row in targetreader:
                    if len(row) < 2:
                        continue
                    if not hit_clients and row[0].strip() == 'Station MAC':
                        hit_clients = True
                        continue

                    if not hit_clients:
                        ap = self._parse_csv_ap(row)
                        if ap:
                            aps.append(ap)
                    else:
                        client = self._parse_csv_client(row)
                        if client:
                            clients.append(client)

        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)
            return ([], [])

        return (aps, clients)

    def _save_csvfiles(self):
        if not self._save_dir:
            return

        filenames = self._get_csvfiles()
        if not filenames:
            return

        for filename in filenames:
            destfile = os.path.basename(filename)
            destfile, ext = os.path.splitext(destfile)
            destfile = destfile + "_" + str(time.time()) + ext
            destfile = os.path.join(self._save_dir, destfile)
            shutil.copy2(filename, destfile)


    def _delete_files(self):
        filenames = self._get_csvfiles()
        for filename in filenames:
            os.unlink(filename)

    def choose_target(self, timeout, ignore=[]):
        """
        :return: waits till a target is chosen
        """
        proc_airodump = subprocess.Popen(self._cmd,
                                         stdout=open(os.devnull, 'w'),
                                         stderr=subprocess.STDOUT)
        time.sleep(timeout)
        proc_airodump.terminate()
        proc_airodump.wait()

        self._save_csvfiles()
        (aps, clients) = self._parse_csvs()
        self._delete_files()
        for cli in clients:
            logging.debug("clients: %s, %d, %s" % (cli.bssid, cli.power,
                                                   cli.station))

        for ap in aps:
            logging.debug("ap: %s", ap.bssid)

        # remove ignored access points
        aps = [ap for ap in aps if ap.bssid not in ignore]
        aps_bssid = [ap.bssid for ap in aps]

        # remove clients without aps (or ignored aps)
        clients = [c for c in clients if c.station in aps_bssid]
        clients = sorted(clients, key=lambda c: c.power, reverse=True)

        if not clients:
            return None, []

        # find ap with strongest client signal
        ap = [ap for ap in aps if ap.bssid == clients[0].station][0]
        clients = [c for c in clients if c.station == ap]
        return ap, clients


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("iface", type=str)
    parsed = parser.parse_args(args[1:])

    IntelCollector(parsed.iface).choose_target(30)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
