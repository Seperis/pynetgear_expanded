"""Module to communicate with Netgear routers using the SOAP v2 API."""
from __future__ import print_function

from collections import namedtuple
import logging
from datetime import timedelta
from time import sleep

import requests
from ipaddress import IPv6Address
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from . import const as c
from . import helpers as h

_LOGGER = logging.getLogger(__name__)

disable_warnings(InsecureRequestWarning)


Device = namedtuple(
    "Device",
    [
        "name",
        "ip",
        "mac",
        "type",
        "signal",
        "link_rate",
        "allow_or_block",
        "device_type",
        "device_model",
        "ssid",
        "conn_ap_mac",
    ],
)

Device2 = namedtuple(
    "Device",
    [
        "name",
        "ip",
        "mac",
        "link",
        "ssid",
        "device",
        "model",
        "parent",
        "os",
    ],
)


class Netgear(object):
    """Represents a session to a Netgear Router."""

    def __init__(
        self,
        password=None,
        host=None,
        user=None,
        port=None,
        ssl=False,
        url=None,
        force_login_v1=False,
        force_login_v2=False,
    ):
        """Initialize a Netgear session."""
        if not url and not host and not port:
            url = h.autodetect_url()

        if not host:
            host = c.DEFAULT_HOST
        if not port:
            port = c.DEFAULT_PORT
        if not user:
            user = c.DEFAULT_USER

        try:
            IPv6Address(host)
        except ValueError:
            pass
        else:
            host = "[%s]" % (host)

        self.username = user
        self.password = password
        self.url = url
        self.host = host
        self.port = port
        self.ssl = ssl
        self.force_login_v1 = force_login_v1
        self.force_login_v2 = force_login_v2
        self.cookie = None
        self.config_started = False
        self._logging_in = False
        self._login_version = 2

        self._info = None

        self.guest_2g_methods = [
            c.GET_GUEST_ACCESS_ENABLED,
            c.GET_GUEST_ACCESS_ENABLED_2,
        ]
        self.guest_5g_methods = [
            c.GET_5G1_GUEST_ACCESS_ENABLED,
            c.GET_5G1_GUEST_ACCESS_ENABLED_2,
            c.GET_5G_GUEST_ACCESS_ENABLED_2,
        ]
        self.guest_2g_set_methods = [
            c.SET_GUEST_ACCESS_ENABLED,
            c.SET_GUEST_ACCESS_ENABLED_2,
        ]
        self.guest_5g_set_methods = [
            c.SET_5G_GUEST_ACCESS_ENABLED,
            c.SET_5G1_GUEST_ACCESS_ENABLED_2,
            c.SET_5G_GUEST_ACCESS_ENABLED_2,
        ]

    @property
    def soap_url(self):
        """SOAP url to connect to the router."""
        if self.url:
            return self.url + "/soap/server_sa/"

        scheme = "https" if self.ssl else "http"
        return "{}://{}:{}/soap/server_sa/".format(
            scheme, self.host, self.port)

    def _get_headers(self, service, method, need_auth=True):
        headers = h.get_soap_headers(service, method)
        # if the stored cookie is not a str then we are
        # probably using the old login method
        if need_auth and isinstance(self.cookie, str):
            headers["Cookie"] = self.cookie
        return headers

    def _post_request(self, headers, message):
        """Post the API request to the router."""
        return requests.post(
            self.soap_url,
            headers=headers,
            data=message,
            timeout=30,
            verify=False,
        )

    def _try_request(
        self,
        message,
        service,
        method,
        params,
        need_auth=True,
        check=True,
        retry=False,
    ):
        """Try a API request to the router."""
        # If we have no cookie (v2) or never called login before (v1)
        # and we need auth, the request will fail for sure.
        if need_auth and not self.cookie:
            if not self.login():
                return False, None

        # update cookie in the headers
        headers = self._get_headers(service, method, need_auth)

        # Try to send the request
        try:
            response = self._post_request(headers, message)
        except requests.exceptions.SSLError:
            self.cookie = None
            if not retry:
                _LOGGER.debug("SSL error, try again after re-login")
                return self._try_request(message, service, method,
                                         params, need_auth, check, retry=True)
            _LOGGER.error("SSLError, re-login failed")
            return False, response
        except requests.exceptions.ReadTimeout as err:
            self.cookie = None
            if not self._logging_in:
                if not retry:
                    return self._try_request(message, service, method, params,
                                             need_auth, check, retry=True)
                _LOGGER.error(
                    "Netgear ReadTimeout, service '%s', method '%s', "
                    "host %s:%s ssl %s"
                    % (service, method, self.host, self.port, self.ssl)
                )
            else:
                _LOGGER.debug("ReadTimeout while logging in "
                              "port %s ssl %s: %s", self.port, self.ssl, err)
            return False, None
        except requests.exceptions.RequestException as err:
            self.cookie = None
            if not self._logging_in:
                _LOGGER.exception(
                    "Error talking to API with service '%s' "
                    "method '%s' host %s:%s ssl %s"
                    % (service, method, self.host, self.port, self.ssl)
                )
            else:
                _LOGGER.debug("RequestException while logging in "
                              "host %s:%s ssl %s: %s",
                              self.host, self.port, self.ssl, err)
            return False, None

        # Check for unauthorized respons
        if need_auth and h.is_unauthorized_response(response):
            # let's discard the cookie because it probably expired (v2)
            # or the IP-bound session expired (v1)
            self.cookie = None
            if not retry:
                _LOGGER.debug(
                    "Unauthorized response, let's login and retry..."
                )
                return self._try_request(message, service, method, params,
                                         need_auth, check, retry=True)
            _LOGGER.error("Unauthorized response, re-login failed")
            return False, response

        success = h.is_valid_response(response)
        if not success:
            if h.is_unauthorized_response(response):
                err_mess = (
                    "Unauthorized response, while need_auth "
                    "was false"
                )
            elif h.is_service_unavailable_response(response):
                if not retry:
                    sleep(3)
                    return self._try_request(message, service, method, params,
                                             need_auth, check, retry=True)
                err_mess = (
                    "503 Service Unavailable after retry, "
                    "the API may be overloaded '%s', '%s'."
                    % (service, method)
                )
            elif h.is_invalid_method_response(response):
                err_mess = (
                    "501 service '%s', method '%s', method not found"
                    % (service, method)
                )
            elif h.is_missing_parameter_response(response):
                err_mess = (
                    "402 missing paramters: "
                    "service '%s', method '%s', params '%s'"
                    % (service, method, params)
                )
            elif h.is_service_not_found_response(response):
                err_mess = (
                    "404 service '%s', method '%s', service not found"
                    % (service, method)
                )
            elif h.is_incomplete_response(response):
                if not retry:
                    sleep(5)
                    return self._try_request(message, service, method, params,
                                             need_auth, check, retry=True)
                err_mess = (
                    "Incomplete response to service '%s', method '%s', "
                    "<ResponseCode> missing: %s\n%s\n%s"
                    % (service,
                       method,
                       response.status_code,
                       str(response.headers),
                       response.text)
                )
            else:
                err_mess = (
                    "Invalid response to '%s', '%s': %s\n%s\n%s"
                    % (service,
                       method,
                       response.status_code,
                       str(response.headers),
                       response.text)
                )
        if not success and not self._logging_in:
            if check:
                _LOGGER.error(err_mess)
        elif not success:
            _LOGGER.debug(err_mess)

        return success, response

    def _make_request(
        self,
        service,
        method,
        params=None,
        body="",
        need_auth=True,
        check=True,
    ):
        """Make an API request to the router."""
        if not body:
            if not params:
                params = ""
            if isinstance(params, dict):
                _map = params
                params = ""
                for k in _map:
                    params += "<" + k + ">" + _map[k] + "</" + k + ">\n"

            body = c.CALL_BODY.format(
                service=c.SERVICE_PREFIX + service,
                method=method,
                params=params,
            )

        message = c.SOAP_REQUEST.format(session_id=c.SESSION_ID, body=body)
        return self._try_request(message, service, method,
                                 params, need_auth, check)

    def config_start(self):
        """
        Start a configuration session.
        For managing router admin functionality (ie allowing/blocking devices)
        """
        _LOGGER.debug("Config start")

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG,
            c.CONFIGURATION_STARTED,
            params={"NewSessionID": c.SESSION_ID},
        )

        self.config_started = success
        return success

    def config_finish(self):
        """
        End of a configuration session.
        Tells the router we're done managing admin functionality.
        """
        _LOGGER.debug("Config finish")
        if not self.config_started:
            return True

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG,
            c.CONFIGURATION_FINISHED,
            params={"NewStatus": "ChangesApplied"},
        )

        self.config_started = not success
        return success

    def _get(
        self,
        service,
        method,
        parseNode=None,
        parse_text=lambda text: text,
        return_node=False,
        check=True,
    ):
        """Get information using a service and method from the router."""
        if parseNode is None:
            parseNode = ".//%sResponse" % (method)

        _LOGGER.debug("Call %s", method)
        success, response = self._make_request(
            service,
            method,
            check=check,
        )
        if not success:
            _LOGGER.debug("Could not successfully get %s", method)
            return None

        success, node = h.find_node(response.text, parseNode)
        if not success:
            _LOGGER.debug("Could not parse response for %s", method)
            return None

        if return_node:
            return node

        return {t.tag: parse_text(t.text) for t in node}

    def _set(self, service, method, params=None):
        """Set router parameters using a service, method and params."""
        _LOGGER.debug("Call %s", method)
        if self.config_started:
            _LOGGER.error(
                "Inconsistant configuration state, "
                "configuration already started"
            )
            if not self.config_finish():
                return False

        if not self.config_start():
            _LOGGER.error("Could not start configuration")
            return False

        success, _ = self._make_request(service, method, params)

        if not success:
            _LOGGER.error(
                "Could not successfully call '%s' with params '%s'",
                method,
                params,
            )
            return False

        if method == c.REBOOT:
            self.config_started = False
            return True

        if not self.config_finish():
            _LOGGER.error(
                "Inconsistant configuration state, "
                "configuration already finished"
            )
            return False

        return True

    def _get_methods(self, service, method_list):
        for idx in range(len(method_list)):
            method = method_list[idx]
            response = self._get(
                service,
                method,
                check=False,
            )
            if response is not None:
                if idx != 0:  # move to front for next time
                    method_list.insert(0, method_list.pop(idx))
                break

        return response

    def _set_methods(
        self, service, method_list, params, get_function, expected
    ):
        for idx in range(len(method_list)):
            method = method_list[idx]
            response = self._set(
                service,
                method,
                params,
            )
            if not response:
                continue
            if get_function() == expected:
                if idx != 0:  # move to front for next time
                    method_list.insert(0, method_list.pop(idx))
                return True

        return False

    def login_try_port(self):
        # first try the currently configured port-ssl combination
        current_port = (self.port, self.ssl)
        if self.login():
            return True

        ports = c.ALL_PORTS.copy()
        if current_port in ports:
            ports.remove(current_port)

        for port in ports:
            self.port = port[0]
            self.ssl = port[1]
            if self.login():
                _LOGGER.info(
                    "Login succeeded using non default port "
                    "'%i' and ssl '%r'.",
                    self.port,
                    self.ssl,
                )
                return True

        # reset original port-ssl
        self.port = current_port[0]
        self.ssl = current_port[1]
        _LOGGER.error("login using all known port-ssl combinations failed.")
        return False

    def login(self):
        """
        Login to the router.

        Will be called automatically by other actions.
        """
        if self._logging_in:
            _LOGGER.debug("Login re-attempt within the login, ignoring.")
            return False
        self._logging_in = True

        # cookie is also used to track if at least
        # one login attempt has been made for v1
        self.cookie = None

        # if a force option is given always start with that method
        if self.force_login_v1:
            self._login_version = 1
        if self.force_login_v2:
            self._login_version = 2

        login_methods = [self.login_v1, self.login_v2]
        for idx in range(0, len(login_methods)):
            login_version = (idx + self._login_version) % len(login_methods)
            login_method = login_methods[login_version - 1]
            if login_method():
                # login succeeded, next time start with this login method
                self._logging_in = False
                self._login_version = login_version
                return True

        # login failed, next time start trying with the other login method
        self._logging_in = False
        self._login_version = self._login_version + 1
        return False

    def login_v2(self):
        _LOGGER.debug("Login v2, port '%i', ssl, '%r'", self.port, self.ssl)

        success, response = self._make_request(
            c.SERVICE_DEVICE_CONFIG,
            c.LOGIN,
            params={"Username": self.username, "Password": self.password},
            need_auth=False,
        )

        if not success:
            return False

        if "Set-Cookie" in response.headers:
            self.cookie = response.headers["Set-Cookie"]
        else:
            _LOGGER.error("Login v2 ok but no cookie...")
            _LOGGER.debug(response.headers)
            return False

        return True

    def login_v1(self):
        _LOGGER.debug("Login v1, port '%i', ssl, '%r'", self.port, self.ssl)

        body = c.LOGIN_V1_BODY.format(
            username=self.username, password=self.password
        )

        success, _ = self._make_request(
            c.SERVICE_PARENTAL_CONTROL, c.LOGIN_OLD, body=body, need_auth=False
        )

        self.cookie = success

        # check login succes with info call
        if self.get_info(use_cache=False) is None:
            return False

        return True

    def get_info(self, use_cache=True):
        """
        Return router informations, like:
        - ModelName
        - DeviceName
        - SerialNumber
        - Firmwareversion
        - FirewallVersion
        - Hardwareversion
        - FirmwareLastUpdate
        - FirmwareLastChecked

        Returns None if error occurred.
        """
        if self._info is not None and use_cache:
            _LOGGER.debug("Info from cache.")
            return self._info

        response = self._get(
            c.SERVICE_DEVICE_INFO,
            c.GET_DEVICE_INFO,
        )
        if response is None:
            return None

        self._info = response
        return self._info

    def get_satellites(self):
        """
        Return list of connected satellites to the router with details.
        Returns None if error occurred.
        """
        node = self._get(
            c.SERVICE_DEVICE_INFO,
            c.GET_ALL_SATELLITES,
            parseNode=".//GetAllSatellitesResponse/CurrentSatellites",
            return_node=True,
        )

        if node is None:
            return None

        return [{t.tag: t.text for t in sat} for sat in node]

    def get_attached_devices(self):
        """
        Return list of connected devices to the router.

        Returns None if error occurred.
        """
        _LOGGER.debug("Get attached devices")

        success, response = self._make_request(
            c.SERVICE_DEVICE_INFO, c.GET_ATTACHED_DEVICES
        )

        if not success:
            _LOGGER.error("Get attached devices failed")
            return None

        success, node = h.find_node(
            response.text, ".//GetAttachDeviceResponse/NewAttachDevice"
        )
        if not success:
            return None
        if node.text is None:
            _LOGGER.error("Error parsing GetAttachDeviceResponse")
            _LOGGER.debug(response.text)
            return None

        devices = []

        # Netgear inserts a double-encoded value for "unknown" devices
        decoded = node.text.strip().replace(
            c.UNKNOWN_DEVICE_ENCODED, c.UNKNOWN_DEVICE_DECODED
        )

        if not decoded or decoded == "0":
            _LOGGER.info("Can't parse attached devices string")
            return devices

        entries = decoded.split("@")

        # First element is the total device count
        entry_count = None
        if len(entries) > 1:
            entry_count = h.convert(entries.pop(0), int)

        # Some devices like MR60 regulary return an entry_count too small
        # Only log when entry_count is too big
        if entry_count is not None and entry_count > len(entries):
            _LOGGER.info(
                "Number of devices should be: %d but is: %d",
                entry_count,
                len(entries),
            )

        for entry in entries:
            info = entry.split(";")

            if len(info) == 0:
                continue

            # Not all routers will report those
            signal = None
            link_type = None
            link_rate = None
            allow_or_block = None
            mac = None
            name = None

            if len(info) >= 8:
                allow_or_block = h.dev_info_get(info[7])
            if len(info) >= 7:
                link_type = h.dev_info_get(info[4])
                link_rate = h.convert(info[5], int)
                signal = h.convert(info[6], int)
            if len(info) >= 4:
                mac = h.dev_info_get(info[3])
            if len(info) >= 3:
                name = h.dev_info_get(info[2])

            if len(info) < 2:
                _LOGGER.warning("Unexpected entry: %s", info)
                continue

            ipv4 = h.dev_info_get(info[1])

            devices.append(
                Device(
                    name,
                    ipv4,
                    mac,
                    link_type,
                    signal,
                    link_rate,
                    allow_or_block,
                    None,
                    None,
                    None,
                    None,
                )
            )

        return devices

    def get_attached_devices_2(self):
        """
        Return list of connected devices to the router with details.

        This call is slower and probably heavier on the router load.

        Returns None if error occurred.
        """
        _LOGGER.debug("Get attached devices 2")

        success, response = self._make_request(
            c.SERVICE_DEVICE_INFO, c.GET_ATTACHED_DEVICES_2
        )
        if not success:
            return None

        success, devices_node = h.find_node(
            response.text, ".//GetAttachDevice2Response/NewAttachDevice"
        )
        if not success:
            return None

        xml_devices = devices_node.findall("Device")
        devices = []
        for d in xml_devices:
            ip = h.xml_get(d, "IP")
            name = h.xml_get(d, "Name")
            mac = h.xml_get(d, "MAC")
            signal = h.convert(h.xml_get(d, "SignalStrength"), int)
            link_type = h.xml_get(d, "ConnectionType")
            link_rate = h.xml_get(d, "Linkspeed")
            allow_or_block = h.xml_get(d, "AllowOrBlock")
            device_type = h.convert(h.xml_get(d, "DeviceType"), int)
            device_model = h.xml_get(d, "DeviceModel")
            ssid = h.xml_get(d, "SSID")
            conn_ap_mac = h.xml_get(d, "ConnAPMAC")
            devices.append(
                Device(
                    name,
                    ip,
                    mac,
                    link_type,
                    signal,
                    link_rate,
                    allow_or_block,
                    device_type,
                    device_model,
                    ssid,
                    conn_ap_mac,
                )
            )

        return devices
        
    def get_attached_devices_2v(self):
        """
        Return list of connected devices to the router with details.

        This call is slower and probably heavier on the router load.

        Returns None if error occurred.
        """
        _LOGGER.debug("Get attached devices 2")

        success, response = self._make_request(
            c.SERVICE_DEVICE_INFO, c.GET_ATTACHED_DEVICES_2
        )
        if not success:
            return None

        success, devices_node = h.find_node(
            response.text, ".//GetAttachDevice2Response/NewAttachDevice"
        )
        if not success:
            return None

        xml_devices = devices_node.findall("Device")
        devices = []
        for d in xml_devices:
            name = h.xml_get(d, "Name")
            ip = h.xml_get(d, "IP")
            mac = h.xml_get(d, "MAC")
            link = h.xml_get(d, "ConnectionType")
            ssid = h.xml_get(d, "SSID")
            device = h.xml_get(d, 'DeviceTypeNameV2')
            model = h.xml_get(d, "DeviceModel")
            parent = h.xml_get(d, "ConnAPMAC")
            os = h.xml_get(d, "DeviceOS")
            
            devices.append(
                Device2(
                    name,
                    ip,
                    mac,
                    link,
                    ssid,
                    device,
                    model,
                    parent,
                    os
                )
            )

        return devices
        
    def get_attached_devices_3(self):
        """
        Alternate function to get_attached_devices_2 to return list of connected devices to the router with details.
        Returns None if error occurred.
        """
        success, response = self._make_request(
            c.SERVICE_DEVICE_INFO, c.GET_ATTACHED_DEVICES_2
        )
        if not success:
            return None

        success, node = h.find_node(
            response.text, ".//GetAttachDevice2Response/NewAttachDevice"
        )
        if not success:
            return None

        xml_lan = node.findall("Device") 
        resp_key=['Name','IP','MAC','ConnectionType','SSID','ChannelNum','SignalStrength','Linkspeed','DeviceTypeNameV2','DeviceModel','ConnAPMAC','DeviceOS','VLANID']
        device_list={}
        lst="device"
        x=0
        for d in xml_lan:
            info={}
            for i in range(0, 13):
                key=resp_key[i]
                value = h.xml_get(d, key)
                info[key] = value
            x=x+1
            device_list[lst + str(x)]=info
        return device_list
        
    def get_traffic_meter(self):
        """
        Return dict of traffic meter stats, like:
        - NewTodayConnectionTime
        - NewTodayUpload
        - NewTodayDownload
        - NewYesterdayConnectionTime
        - NewYesterdayUpload
        - NewYesterdayDownload
        - NewWeekConnectionTime
        - NewWeekUpload
        - NewWeekDownload
        - NewMonthConnectionTime
        - NewMonthUpload
        - NewMonthDownload
        - NewLastMonthConnectionTime
        - NewLastMonthUpload
        - NewLastMonthDownload

        Returns None if error occurred.
        """

        def parse_text(text):
            """
            there are three kinds of values in the returned data
            This function parses the different values and returns
            (total, avg), timedelta or a plain float
            """

            def tofloats(lst):
                return (float(t) for t in lst)

            try:
                text = text.replace(",", "")  # 25,350.10 MB
                if "--" in text:
                    return None
                if "/" in text:  # "6.19/0.88" total/avg
                    return tuple(tofloats(text.split("/")))
                if ":" in text:  # 11:14 hr:mn
                    hour, mins = tofloats(text.split(":"))
                    return timedelta(hours=hour, minutes=mins)
                return float(text)
            except ValueError:
                _LOGGER.error("Error parsing traffic meter stats: %s", text)
                return None

        return self._get(
            c.SERVICE_DEVICE_CONFIG,
            "GetTrafficMeterStatistics",
            parse_text=parse_text,
        )

    def allow_block_device(self, mac_addr, device_status=c.BLOCK):
        """
        Allow or Block a device via its Mac Address.
        Pass in the mac address for the device that you want to set.
        Pass in the device_status you wish to set the device to:
        Allow (allow device to access the network)
        or Block (block the device from accessing the network).
        """
        return self._set(
            c.SERVICE_DEVICE_CONFIG,
            "SetBlockDeviceByMAC",
            {"NewAllowOrBlock": device_status, "NewMACAddress": mac_addr},
        )

    def reboot(self):
        """Reboot the router"""
        return self._set(c.SERVICE_DEVICE_CONFIG, c.REBOOT)

    def check_new_firmware(self):
        """
        Check for new firmware and return dict like:
        - CurrentVersion
        - NewVersion
        - ReleaseNote
        """
        return self._get(
            c.SERVICE_DEVICE_CONFIG,
            c.CHECK_NEW_FIRMWARE,
        )

    def update_new_firmware(self):
        """Issue a firmware update of the router."""
        return self._set(
            c.SERVICE_DEVICE_CONFIG,
            c.UPDATE_NEW_FIRMWARE,
            {"YesOrNo": "1"},
        )

    def get_system_info(self):
        """
        Get system Info and return dict like:
        - NewCPUUtilization
        - NewPhysicalMemory
        - NewMemoryUtilization
        - NewPhysicalFlash
        - NewAvailableFlash
        """
        return self._get(
            c.SERVICE_DEVICE_INFO,
            c.GET_SYSTEM_INFO,
        )

    def check_ethernet_link(self):
        """
        Check the ethernet link status and return dict like:
        - NewEthernetLinkStatus
        """
        return self._get(
            c.SERVICE_WAN_ETHERNET_LINK_CONFIG,
            c.GET_ETHERNET_LINK_STATUS,
        )

    def get_device_config_info(self):
        """
        Get Device Config Info and return dict like:
        - BlankState
        - NewBlockSiteEnable
        - NewBlockSiteName
        - NewTimeZone
        - NewDaylightSaving
        """
        return self._get(
            c.SERVICE_DEVICE_CONFIG,
            c.GET_DEVICE_CONFIG_INFO,
        )

    def get_block_device_enable_status(self):
        """Get Block Device Enable Status and return boolean."""
        response = self._get(
            c.SERVICE_DEVICE_CONFIG, c.GET_BLOCK_DEVICE_ENABLE_STATUS
        )
        return h.zero_or_one_dict_to_boolean(response)

    def set_block_device_enable(self, value=False):
        """Set SetBlockDeviceEnable."""
        value = h.value_to_zero_or_one(value)
        return self._set(
            c.SERVICE_DEVICE_CONFIG,
            c.SET_BLOCK_DEVICE_ENABLE,
            {"NewBlockDeviceEnable": value},
        )

    def get_traffic_meter_enabled(self):
        """Get Traffic Meter Enabled and return boolean."""
        response = self._get(
            c.SERVICE_DEVICE_CONFIG, c.GET_TRAFFIC_METER_ENABLED
        )
        return h.zero_or_one_dict_to_boolean(response)

    def get_traffic_meter_options(self):
        """
        Get Traffic Meter Options and return dict like:
        - NewControlOption
        - NewMonthlyLimit
        - RestartHour
        - RestartMinute
        - RestartDay
        """
        return self._get(c.SERVICE_DEVICE_CONFIG, c.GET_TRAFFIC_METER_OPTIONS)

    def enable_traffic_meter(self, value=False):
        """Set EnableTrafficMeter."""
        value = h.value_to_zero_or_one(value)
        return self._set(
            c.SERVICE_DEVICE_CONFIG,
            c.ENABLE_TRAFFIC_METER,
            {"NewTrafficMeterEnable": value},
        )
    
    def is_dlna_enabled(self):	
        """
        Check if DLNA is enabled
        """	
        return self._get(c.SERVICE_DEVICE_CONFIG ,"IsDLNAEnabled",)

    def is_dlna_supported(self):	
        """
        Check if DLNA is supported
        """	
        return self._get(c.SERVICE_DEVICE_CONFIG ,"IsDLNASupported",)
        
    def get_time_zone_info(self):	
        """
        Get time zone information
        """	
        return self._get(c.SERVICE_DEVICE_CONFIG ,"GetTimeZoneInfo",)

    def get_lan_config_sec_info(self):
        """
        Get LAN Config Security Info and return dict like:
        - NewLANSubnet
        - NewWANLAN_Subnet_Match
        - NewLANMACAddress
        - NewLANIP
        - NewDHCPEnabled
        """
        return self._get(
            c.SERVICE_LAN_CONFIG_SECURITY,
            c.GET_LAN_INFO,
        )

    def get_wan_ip_con_info(self):
        """
        Get WAN IP Connection Info and return dict like:
        - NewEnable
        - NewConnectionType
        - NewExternalIPAddress
        - NewSubnetMask
        - NewAddressingType
        - NewDefaultGateway
        - NewMACAddress
        - NewMACAddressOverride
        - NewMaxMTUSize
        - NewDNSEnabled
        - NewDNSServers
        """
        return self._get(
            c.SERVICE_WAN_IP_CONNECTION,
            c.GET_WAN_INFO,
        )
    
    def get_port_mapping_info(self):	
        """
        Get Port mapping info
        """	
        return self._get(c.SERVICE_WAN_IP_CONNECTION ,"GetPortMappingInfo",)

    def get_parental_control_enable_status(self):
        """Get parental control enable status and return boolean."""
        response = self._get(
            c.SERVICE_PARENTAL_CONTROL, c.GET_PARENTAL_CONTROL_ENABLE_STATUS
        )
        return h.zero_or_one_dict_to_boolean(response)

    def enable_parental_control(self, value=False):
        """Set EnableParentalControl."""
        value = h.value_to_zero_or_one(value)
        return self._set(
            c.SERVICE_PARENTAL_CONTROL,
            c.ENABLE_PARENTAL_CONTROL,
            {"NewEnable": value},
        )

    def get_all_mac_addresses(self):
        """
        Get All MAC Addresses for parental control and return dict like:
        - AllMACAddresses
        """
        return self._get(
            c.SERVICE_PARENTAL_CONTROL,
            c.GET_ALL_MAC_ADDRESSES,
        )

    def get_dns_masq_device_id(self):
        """
        Get DNS Masq Device ID and return dict like:
        - NewDeviceID
        """
        return self._get(
            c.SERVICE_PARENTAL_CONTROL,
            c.GET_DNS_MASQ_DEVICE_ID,
        )

    def get_support_feature_list(self):
        """
        Get Support Feature List and return dict like:
        - DynamicQoS
        - OpenDNSParentalControl
        - MaxMonthlyTrafficLimitation
        - AccessControl
        - SpeedTest
        - GuestNetworkSchedule
        - TCAcceptance
        - SmartConnect
        - AttachedDevice
        - NameNTGRDevice
        - PasswordReset
        """
        return self._get(
            c.SERVICE_DEVICE_INFO,
            c.GET_SUPPORT_FEATURE_LIST_XML,
            parseNode=(
                ".//%sResponse/newFeatureList/features"
                % (c.GET_SUPPORT_FEATURE_LIST_XML)
            ),
        )
    
    def get_system_uptime(self):	
        """
        Get system uptime
        """	
        return self._get(c.SERVICE_DEVICE_INFO ,"GetSysUpTime",)

    def set_speed_test_start(self):
        """Start the speed test."""
        return self._set(
            c.SERVICE_ADVANCED_QOS,
            c.SET_SPEED_TEST_START,
        )

    def get_speed_test_result(self):
        """
        Get the speed test result and return dict like:
        - NewOOKLAUplinkBandwidth
        - NewOOKLADownlinkBandwidth
        - AveragePing

        Response Code = 1 means in progress
        """
        _LOGGER.debug("Retrieving speed test result")
        for _retry in range(1, 30+1):
            success, response = self._make_request(
                c.SERVICE_ADVANCED_QOS,
                c.GET_SPEED_TEST_RESULT,
                check=False,
            )
            if response.status_code != 200:
                _LOGGER.warning(
                    "Could not successfully get %s", c.GET_SPEED_TEST_RESULT
                )
                return None

            success, node = h.find_node(response.text, ".//ResponseCode")
            if not success:
                _LOGGER.warning("Could not parse response for speed test result")
                return None

            if node.text in ["0", "000", "0000"]:  # new test done
                _LOGGER.debug("new speed test retrieved")
                break
            if node.text in ["1", "001"]:  # test in progress
                if _retry >= 30:
                    _LOGGER.warning(
                        "speed test still in progress while maximum"
                        " retries reached, returning partial results"
                    )
                    continue
                _LOGGER.debug(
                    "speed test still in progress after %i attempts, "
                    "sleep for 2 seconds",
                    _retry
                )
                sleep(2)
                continue
            if node.text == "501":  # old test result
                _LOGGER.warning("old speed test result returned")
                break
            _LOGGER.error(
                "Unexpected return code for speed test: '%s'", node.text
            )
            return None

        success, node = h.find_node(
            response.text, ".//%sResponse" % (c.GET_SPEED_TEST_RESULT)
        )
        if not success:
            _LOGGER.warning("Could not parse response for speed test result")
            return None

        return {t.tag: t.text for t in node}

    def get_new_speed_test_result(self):
        """
        Request a new speed test and get the results and return dict like:
        - NewOOKLAUplinkBandwidth
        - NewOOKLADownlinkBandwidth
        - AveragePing

        Response Code = 1 means in progress
        """
        if not self.set_speed_test_start():
            return None
        return self.get_speed_test_result()

    def get_qos_enable_status(self):
        """
        Get QoS Enable Status and return dict like:
        - NewQoSEnableStatus
        """
        response = self._get(
            c.SERVICE_ADVANCED_QOS,
            c.GET_QOS_ENABLE_STATUS,
        )
        return h.zero_or_one_dict_to_boolean(response)

    def set_qos_enable_status(self, value=False):
        """Set QoS Enable Status."""
        value = h.value_to_zero_or_one(value)
        return self._set(
            c.SERVICE_ADVANCED_QOS,
            c.SET_QOS_ENABLE_STATUS,
            {"NewQoSEnable": value},
        )

    def get_bandwidth_control_options(self):
        """
        Get Bandwidth Control Options and return dict like:
        - NewUplinkBandwidth
        - NewDownlinkBandwidth
        - NewSettingMethod
        """
        return self._get(
            c.SERVICE_ADVANCED_QOS,
            c.GET_BANDWIDTH_CONTROL_OPTIONS,
        )

    def get_2g_guest_access_enabled(self):
        """Get 2.4G Guest Access Enabled and return boolean."""
        response = self._get_methods(
            c.SERVICE_WLAN_CONFIGURATION,
            self.guest_2g_methods,
        )
        return h.zero_or_one_dict_to_boolean(response)

    def get_5g_guest_access_enabled(self):
        """Get 5G Guest Access Enabled and return boolean"""
        response = self._get_methods(
            c.SERVICE_WLAN_CONFIGURATION,
            self.guest_5g_methods,
        )
        return h.zero_or_one_dict_to_boolean(response)

    def set_2g_guest_access_enabled(self, value=False):
        """Set Guest Access Enabled."""
        value = h.value_to_zero_or_one(value)
        return self._set_methods(
            c.SERVICE_WLAN_CONFIGURATION,
            self.guest_2g_set_methods,
            {"NewGuestAccessEnabled": value},
            self.get_2g_guest_access_enabled,
            h.zero_or_one_to_boolean(value),
        )

    def set_5g_guest_access_enabled(self, value=False):
        """Set 5G Guest Access Enabled."""
        value = h.value_to_zero_or_one(value)
        return self._set_methods(
            c.SERVICE_WLAN_CONFIGURATION,
            self.guest_5g_set_methods,
            {"NewGuestAccessEnabled": value},
            self.get_5g_guest_access_enabled,
            h.zero_or_one_to_boolean(value),
        )

    def get_2g_wpa_security_keys(self):
        """
        Get 2.4G WPA Security Keys and return dict like:
        - NewWPAPassphrase
        """
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_WPA_SECURITY_KEYS,
        )

    def get_5g_wpa_security_keys(self):
        """
        Get 5G WPA Security Keys and return dict like:
        - NewWPAPassphrase
        """
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_5G_WPA_SECURITY_KEYS,
        )

    def get_5g_info(self):
        """
        Get 5G Info and return dict like:
        - NewEnable
        - NewSSIDBroadcast
        - NewStatus
        - NewSSID
        - NewRegion
        - NewChannel
        - NewWirelessMode
        - NewBasicEncryptionModes
        - NewWEPAuthType
        - NewWPAEncryptionModes
        - NewWLANMACAddress
        """
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_5G_INFO,
        )

    def get_2g_info(self):
        """
        Get 2G Info and return dict like:
        - NewEnable
        - NewSSIDBroadcast
        - NewStatus
        - NewSSID
        - NewRegion
        - NewChannel
        - NewWirelessMode
        - NewBasicEncryptionModes
        - NewWEPAuthType
        - NewWPAEncryptionModes
        - NewWLANMACAddress
        """
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_2G_INFO,
        )

    def get_2g_guest_access_network_info(self):
        """
        Get 2.4G Guest Access Network Info and return dict like:
        - NewSSID
        - NewSecurityMode
        - NewKey
        - UserSetSchedule
        - Schedule
        """
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_GUEST_ACCESS_NETWORK_INFO,
        )

    def get_5g_guest_access_network_info(self):
        """
        Get 5G Guest Access Network Info and return dict like:
        - NewSSID
        - NewSecurityMode
        - NewKey
        - UserSetSchedule
        - Schedule
        """
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, c.GET_5G_GUEST_ACCESS_NETWORK_INFO
        )
    def get_available_channel_2g(self):
        """
        GetAvailableChanneland return dict like:
        - NewAvailableChannel
        """
        success, response=self._make_request(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_AVAILABLE_CHANNEL,
            params={"NewBand": "2.4G"},
        )
        
        if not success:
            _LOGGER.error("Get available channel failed")
            return None
            
        success, node = h.find_node(
            response.text, ".//GetAvailableChannelResponse"
        )
        
        if not success:
            _LOGGER.error('Node failed?')
            return None
            
        if node.text is None:
            _LOGGER.error("Error parsing GetAvailableChannelResponse")
            _LOGGER.debug(response.text)
            return None
            
        parse_text=lambda text: text    
        return {t.tag: parse_text(t.text) for t in node}
        
    def get_available_channel_5g(self):
        """
        GetAvailableChanneland return dict like:
        - NewAvailableChannel
        """
        success, response=self._make_request(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_AVAILABLE_CHANNEL,
            params={"NewBand": "5G"},
        )
        
        if not success:
            _LOGGER.error("Get available channel failed")
            return None
            
        success, node = h.find_node(
            response.text, ".//GetAvailableChannelResponse"
        )
        
        if not success:
            _LOGGER.error('Node failed?')
            return None
            
        if node.text is None:
            _LOGGER.error("Error parsing GetAvailableChannelResponse")
            _LOGGER.debug(response.text)
            return None
            
        parse_text=lambda text: text    
        return {t.tag: parse_text(t.text) for t in node}
    def get_region(self):	
        """
        Get region
        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetRegion",)  

    def get_smart_connect_enabled(self):
        """Get Smart Connect Enabled and return boolean."""
        response = self._get(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_SMART_CONNECT_ENABLED,
        )
        return h.zero_or_one_dict_to_boolean(response)

    def set_smart_connect_enabled(self, value=False):
        """Set Smart Connect Enable."""
        value = h.value_to_zero_or_one(value)
        return self._set(
            c.SERVICE_WLAN_CONFIGURATION,
            c.SET_SMART_CONNECT_ENABLED,
            {"NewSmartConnectEnable": value},
        )
    
    def get_time_info(self):	
        """
        Gettime info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_TIME,c.GET_TIME_INFO,)

   def get_available_channel_2g(self):
        """
        GetAvailableChanneland return dict like:
        - NewAvailableChannel
        """
        success, response=self._make_request(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_AVAILABLE_CHANNEL,
            params={"NewBand": "2.4G"},

        )
        
        if not success:
            _LOGGER.error("Get available channel failed")
            return None
            
        success, node = h.find_node(
            response.text, ".//GetAvailableChannelResponse"
        )
        
        if not success:
            _LOGGER.error('Node failed?')
            return None
            
        if node.text is None:
            _LOGGER.error("Error parsing GetAvailableChannelResponse")
            _LOGGER.debug(response.text)
            return None
            
        parse_text=lambda text: text    
        return {t.tag: parse_text(t.text) for t in node}
        
    def get_available_channel_5g(self):
        """
        GetAvailableChanneland return dict like:
        - NewAvailableChannel
        """
        success, response=self._make_request(
            c.SERVICE_WLAN_CONFIGURATION,
            c.GET_AVAILABLE_CHANNEL,
            params={"NewBand": "5G"},

        )
        
        if not success:
            _LOGGER.error("Get available channel failed")
            return None
            
        success, node = h.find_node(
            response.text, ".//GetAvailableChannelResponse"
        )
        
        if not success:
            _LOGGER.error('Node failed?')
            return None
            
        if node.text is None:
            _LOGGER.error("Error parsing GetAvailableChannelResponse")
            _LOGGER.debug(response.text)
            return None
            
        parse_text=lambda text: text    
        return {t.tag: parse_text(t.text) for t in node}

        
    def get_connection_type_info(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WAN_IP_CONNECTION ,"GetConnectionTypeInfo",)
      
    def get_wireless_mode(self):	

        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetWirelessMode",)

    def get_5g_wireless_mode(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"Get5GWirelessMode",)
        
    def get_channel_info(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetChannelInfo",)
				
    def get_5g_channel_info(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"Get5GChannelInfo",)
				
    def get_ssid(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetSSID",)
				
    def get_5g_ssid(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"Get5GSSID",)

    def get_ssid_broadcast(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetSSIDBroadcast",)


    def get_wep_security_keys(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetWEPSecurityKeys",)
				
    def get_5g_wep_security_keys(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable
        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"Get5GWEPSecurityKeys",)		
				
    def get_wpa_security_keys(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetWPASecurityKeys",)
        
    def get_5g_wpa_security_keys(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"Get5GWPASecurityKeys",)
        
    def get_wps_mode(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetWPSMode",)    
		
    def get_wps_pin_info(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetWPSPINInfo",)
        
    def is_5g_supported(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"Is5GSupported",)

    def get_support_mode(self):	
        """
        Get Support Mode
        """	
        return self._get(c.SERVICE_WLAN_CONFIGURATION ,"GetSupportMode",)
        
    def get_internet_port_info(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_WAN_IP_CONNECTION ,"GetInternetPortInfo",)
        
    def get_block_site_info(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_DEVICE_CONFIG ,"GetBlockSiteInfo",)
        
    def get_system_logs(self):	
        """
        Get System Logs
        Still in progress

        """	
        return self._get(c.SERVICE_DEVICE_INFO ,"GetSystemLogs",)

    def get_device_list_all(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_DEVICE_CONFIG ,"GetDeviceListAll",)

    def get_device_list_by_mode(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_DEVICE_CONFIG ,"GetDeviceListByMode",)  

    def get_qos_rules(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_DEVICE_CONFIG ,"GetQoSRules",) 
        
        
    def get_attach_device(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_DEVICE_INFO ,"GetAttachDevice",)
        
    def get_static_route_tbl(self):	
        """
        Get 2G Info and return dict like:
        - NewEnable

        """	
        return self._get(c.SERVICE_DEVICE_CONFIG,"GetStaticRouteTbl",)
        
        
    def get_support_mode2(self):	
        """
        Get Support Mode
        """	
        success, response=self._make_request(
		c.SERVICE_WLAN_CONFIGURATION,
		"GetSupportMode",
		params={"NewBand": "2.4G"},)

        if not success:
            _LOGGER.error("Get support mode failed")
            return None
            
        success, node = h.find_node(
            response.text, ".//GetSupportModeResponse"
        )
        
        if not success:
            _LOGGER.error('Node failed?')
            return None
            
        if node.text is None:
            _LOGGER.error("Error parsing GetSupportModeResponse")
            _LOGGER.debug(response.text)
            return None
            
        parse_text=lambda text: text    
        return {t.tag: parse_text(t.text) for t in node}
        
    def get_2g_wireless3_info(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetWireless3Info"
        )
        
    def get_5g_wireless3_info(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "Get5GWireless3Info"
        )
        
    def get_wireless1_enabled(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetWireless1Enabled"
        )
        
    def get_wireless1_separate_ssid_enabled(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetWireless1SeparateSSIDEnabled"
        )
        
    def get_wireless1_schedule(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetWireless1Schedule"
        )
        
    def get_wireless2_schedule(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetWireless2Schedule"
        )
        
    def get_wireless3_schedule(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetWireless3Schedule"
        )

    def get_guest_schedule(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetGuestSchedule"
        )
        
    def get_guest_portal(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetGuestPortal"
        )
 
    def get_guest_portal_custom(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetGuestPortalCustom"
        )
 
    def get_wlan_vlan_profile(self):
        return self._get(
            c.SERVICE_WLAN_CONFIGURATION, "GetWLANVLANProfile"
        )

    def get_vlan_profile_by_index(self):
        success, response=self._make_request(
            c.SERVICE_DEVICE_CONFIG, 
            "GetVLANProfileVIDByIndex",
            params={"Index": "1"}
        )
        if not success:
            _LOGGER.error("get_vlan_profile_by_index failed")
            return None
            
        success, node = h.find_node(
            response.text, ".//GetVLANProfileVIDByIndexResponse"
        )
        if not success:
            _LOGGER.error('Node failed?')
            return None
            
        if node.text is None:
            _LOGGER.error("Error parsing GetVLANProfileVIDByIndexResponse")
            _LOGGER.debug(response.text)
            return None
            
        parse_text=lambda text: text    
        return {t.tag: parse_text(t.text) for t in node}  
 
    def get_remote_access(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetRemoteAccess"
        )
        
    def get_configuration_timestamp(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetConfigurationTimestamp"
        )
        
    def get_vlan_profile_config(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetVLANProfileConfiguration"
        )
        
    def get_all_ethernet_vlan_config(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetAllEthernetVlanConfiguration"
        )
        
    def get_mdns_config(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetMdnsConfiguration"
        )
        
    def get_mdns_policy_tbl(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetMdnsPolicyTbl"
        )        

        
    def get_all_config_lan(self):
        return self._get(
            c.SERVICE_LAN_CONFIG_SECURITY, "GetAllConfigLAN",
            parseNode=".//GetAllConfigLANResponse/CurrentLANInfo/LANInfo",
        )		

    def get_config_mac_reservation(self):
        success, response=self._make_request(
            c.SERVICE_LAN_CONFIG_SECURITY, 
            "GetConfigMACReservation",
            params={"NewLANID": "lan2"}
        )
        if not success:
            _LOGGER.error("get_config_mac_reservation failed")
            return None
            
        success, node = h.find_node(
            response.text, ".//GetConfigMACReservationResponse"
        )
        if not success:
            _LOGGER.error('Node failed?')
            return None
            
        if node.text is None:
            _LOGGER.error("Error parsing GetConfigMACReservationResponse")
            _LOGGER.debug(response.text)
            return None
            
        parse_text=lambda text: text    
        return {t.tag: parse_text(t.text) for t in node}   

        

    def get_fail_satellites_list(self):
        """
        Return list of connected satellites to the router with details.
        Returns None if error occurred.
        """
        return self._get(
            c.SERVICE_DEVICE_INFO, "GetFailSatelliteList"
        )
        
    def get_missing_satellites(self):
        """
        Return list of connected satellites to the router with details.
        Returns None if error occurred.
        """
        return self._get(
            c.SERVICE_DEVICE_INFO, "GetMissingSatellites",
            parseNode=".//GetMissingSatellitesResponse/MissingSatelliteList"
        )       
        
   
    def get_base_lan_status(self):
        """
        Return list of connected satellites to the router with details.
        Returns None if error occurred.
        """
        return self._get(
            c.SERVICE_DEVICE_INFO, "GetBaseLANStatus"
        )   

    def get_all_satellite_lan_status_v1(self):
        """
        Return list of connected satellites to the router with details.
        Returns None if error occurred.
        """
        return self._get(
            c.SERVICE_DEVICE_INFO, 
			"GetAllSatelliteLANStatus",
			parseNode=".//GetAllSatelliteLANStatusResponse/CurrentSatellites"
        )
        
        
    def get_all_satellite_lan_status_v2(self):
        """
        Return list of connected satellites to the router with details.
        Returns None if error occurred.
        """       
        success, response = self._make_request(
            c.SERVICE_DEVICE_INFO, 
            "GetAllSatelliteLANStatus"
        )
        if not success:
            return None

        success, devices_node = h.find_node(
            response.text, ".//GetAllSatelliteLANStatusResponse/CurrentSatellites"
        )
        if not success:
            return None
            
    def get_all_satellite_lan_status(self):
        """
        Return list of connected satellites to the router with details.
        Returns None if error occurred.
        """               
        node = self._get(
            c.SERVICE_DEVICE_INFO,
            "GetAllSatelliteLANStatus",
            parseNode=".//GetAllSatelliteLANStatusResponse/CurrentSatellites",
            return_node=True,
        )
        if node is None:
            return None

        return [{t.tag: t.text for t in sat} for sat in node]       
        
    def get_ethernet_radius_config(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetEthernetRadiusConfiguration"
        )       
        
    def get_base_ethernet_radius_security(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetBaseEthernetRadiusSecurity"
        )       
              
    def get_satellite_ethernet_radius_security(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetSatelliteEthernetRadiusSecurity"
        )              
        
    def get_mvpn_status(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetMVPNStatus"
        )              
  
    def get_mvpn_remote_isolation(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetMVPNRemoteIsolation"
        )        
    def get_content_filter(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, "GetContentFilter"
        )        

    def get_mac_acl_info_all_v1(self):
        return self._get(
            c.SERVICE_DEVICE_CONFIG, 
            "GetMacACLInfoAll",
            parseNode=".//GetMacACLInfoAllResponse/MacACLInfo",
            return_node=True,
        )     

        if node is None:
            return None

        return [{t.tag: t.text for t in sat} for sat in node]


    def get_mac_acl_info_all(self):
        success, response = self._make_request(
            c.SERVICE_DEVICE_CONFIG, "GetMacACLInfoAll"
        )
        if not success:
            return None

        success, devices_node = h.find_node(
            response.text, ".//GetMacACLInfoAllResponse/MacACLInfo"
        )
        if not success:
            return None        
