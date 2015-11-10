__author__ = 'yannay'

class AccessPoint:
    """
        Holds data for an Access Point (aka Router)
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

