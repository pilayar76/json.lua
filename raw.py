# Standard Library
import copy
import logging
import re
import sys
import traceback

# Third Party Library
from nested_lookup import get_all_keys, nested_lookup

# DNE Library
import orchestrator.core.utils.custom as custom_utils

logger = logging.getLogger(__name__)


class RawApi:
    def __init__(self, **kwargs):
        self.validation_msg = ""
        self.stage_err = ""
        # fix for bug 3378
        self.l2vpn_service_attribute = ""
        self.l2vpn_ac_service_attribute = ""
        # fix for bug 3177
        self.es_db_model = None
        self.generic_utils = custom_utils.GenericUtils()
        model = kwargs.get("model", None)
        if model is not None:
            self.es_db_model = copy.deepcopy(model)
            del self.es_db_model["_id"]
            self.es_db_model["service"]["serviceOperStatus"] = True
            self.es_db_model["service"]["serviceOperMessage"] = ""

            for item in self.es_db_model["service"]["pes"]:
                item["lagOperStatus"] = True
                item["lagOperMessage"] = ""
                for port in item["ports"]:
                    port["linkOperStatus"] = True
                    port["linkOperMessage"] = ""

    # Fix for Bug 3763
    # Precheck failure messages to be added to DB
    # Format local and stage error messages
    @property
    def err_in_stage(self):
        # remove trailing ',' from the error string
        self.validation_msg = f"{self.stage_err}: " + self.validation_msg.strip(",")
        return self.validation_msg

    @err_in_stage.setter
    def err_in_stage(self, name):
        self.stage_err = name

    def format_local_err_msg(self, msg):
        formatted_msg = f"{self.stage_err}: " + msg.strip(",")
        return formatted_msg

    def format_message(self, device_name, cmd_name, expected_response, actual_response):
        """
            generic method to format orch messages for pre and post check commands

            Args:
                device_name: name of the device
                cmd_name: command name
                expected_response : expected conditions
                actual_response : parsed and validated results
            Returns:
                message

            Raises:
                NA
        """
        message = f"Command:{cmd_name} Device:{device_name} Expected:{expected_response} Actual:{actual_response},"
        return message

    def showisisadjacecny(self, pes):  # noqa: ignore=C901
        """
         combined method for Pre-check and Post-check to validate show isis Adjacency core check

        Args:
            pes: list containing the json o/p from dial

        Returns:
            status: True or False

        Raises:
            Exception
        """
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show isis adjacency"
        expected_resp = f"Atleast one Active adjacency with adjacency state as UP "

        try:
            local_status_msg = ""
            active_count = 0
            # iterate through the o/p showisisadjacecny

            for protocol_item in pes["showIsisAdjacency"]["rpc-reply"]["data"]["network-instances"]["network-instance"][
                "protocols"
            ]["protocol"]:
                if protocol_item["identifier"] == "ISIS" and protocol_item["name"] == "CORE":
                    for level_item in protocol_item["levels"]["level"]:
                        for adjacency_item in level_item["adjacencies"]["adjacency"]:
                            # adjacency state may come as null hence need to check for None else it will through
                            # exception
                            if adjacency_item["adjacency-state"] is not None:
                                if re.match(adjacency_item["adjacency-state"], "up", re.I):

                                    active_count += 1

            # active count number isis adjacency matching the state
            if active_count < 1:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"No Active adjacency with adjacency state as UP "
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

                self.validation_msg += local_status_msg
                logger.error(local_status_msg)
                # fix for bug 3177
                if self.es_db_model is not None:
                    item = self.es_db_model["service"]
                    item["serviceOperStatus"] = False
                    item["serviceOperMessage"] = self.format_local_err_msg(local_status_msg)

                return False

            # if there is at-least one active count
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"{active_count} Active adjacency with adjacency state as UP "
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.debug(local_status_msg)
            return True

        except Exception as err:
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(err)
            logger.error("\n" + str(ex_info[1]))
            logger.error("\n" + traceback.extract_tb(tb).__str__())
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)
            # fix for bug 3177
            if self.es_db_model is not None:
                item = self.es_db_model["service"]
                item["serviceOperStatus"] = False
                item["serviceOperMessage"] = self.format_local_err_msg(local_status_msg)

            return False

    def showbgpevpnsummary(self, pes):  # noqa: ignore=C901
        """
               combined method for Pre-check and Post-check to validate show bgp l2vpn evpn summary

               Args:
                   pes: list containing the json o/p from dial

               Returns:
                   status: True or False

               Raises:
                   Exception
        """
        logger.info(f"Entering showbgpevpnsummary validation for {pes.get('peName')}")
        logger.info(
            f"showbgpevpnsummary command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showBgpEvpnSummary')}"
        )
        status = True
        count_active = 0
        device_name = pes["peName"]
        cmd_name = "show bgp l2vpn evpn summary"
        expected_resp = (
            f"minimum of one session to route-reflector for L2VPN EVPN with prefixes received" f" in active state"
        )

        try:
            # iterate through the o/p of showBgpevpnsummary
            for item in pes["showBgpEvpnSummary"]["rpc-reply"]["data"]["network-instances"]["network-instance"][
                "protocols"
            ]["protocol"]["bgp"]["neighbors"]["neighbor"]:
                l2evpn_list = nested_lookup(key="state", document=item)
                for element in l2evpn_list:
                    if element["afi-safi-name"]["#text"] == "idx:L2VPN_EVPN":
                        if element["active"] != "true":
                            pass
                        else:
                            if int(element["prefixes"]["received"]) >= 1:
                                count_active += 1

            if count_active < 1:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"No active Neighbors"
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += local_status_msg
                logger.error(local_status_msg)
                status = False
                # fix for bug 3177
                if self.es_db_model is not None:
                    item = self.es_db_model["service"]
                    item["serviceOperStatus"] = False
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    item["serviceOperMessage"] = self.format_local_err_msg(local_status_msg)

            if status:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"{count_active} active Neighbors Present"
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

            logger.debug(local_status_msg)
            logger.info(f"Exiting showbgpevpnsummary after validation for {pes.get('peName')}")
            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)
            # fix for bug 3177
            if self.es_db_model is not None:
                item = self.es_db_model["service"]
                item["serviceOperStatus"] = False
                item["serviceOperMessage"] = self.format_local_err_msg(local_status_msg)

            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)
            # fix for bug 3177
            if self.es_db_model is not None:
                item = self.es_db_model["service"]
                item["serviceOperStatus"] = False
                item["serviceOperMessage"] = self.format_local_err_msg(local_status_msg)

            return False

    def showbgpipv4summary(self, pes):  # noqa: ignore=C901
        """
                combined method for Pre-check and Post-check to validate show bgp ipv4 unicast summary

                Args:
                    pes: list containing the json o/p from dial

                Returns:
                    status: True or False

                Raises:
                    Exception
        """

        status = True
        count_active = 0
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show bgp ipv4 unicast summary"
        expected_resp = (
            f"minimum of one session to route-reflector for IPv4 Unicast with prefixes received" f" in active state"
        )

        try:
            for item in pes["showBgpIpv4Summary"]["rpc-reply"]["data"]["network-instances"]["network-instance"][
                "protocols"
            ]["protocol"]["bgp"]["neighbors"]["neighbor"]:
                l2evpn_list = nested_lookup(key="state", document=item)
                for element in l2evpn_list:
                    if element["afi-safi-name"]["#text"] == "idx:IPV4_UNICAST":
                        if element["active"] != "true":
                            pass
                        else:
                            if int(element["prefixes"]["received"]) >= 1:
                                count_active += 1

            if count_active < 1:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"No active Neighbors"
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += local_status_msg
                logger.error(local_status_msg)

                status = False
                # fix for bug 3177
                if self.es_db_model is not None:
                    item = self.es_db_model["service"]
                    item["serviceOperStatus"] = False
                    item["serviceOperMessage"] = self.format_local_err_msg(local_status_msg)

            if status:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"{count_active} active Neighbors Present"
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                logger.debug(local_status_msg)

            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)
            # fix for bug 3177
            if self.es_db_model is not None:
                item = self.es_db_model["service"]
                item["serviceOperStatus"] = False
                item["serviceOperMessage"] = self.format_local_err_msg(local_status_msg)

            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)
            # fix for bug 3177
            if self.es_db_model is not None:
                item = self.es_db_model["service"]
                item["serviceOperStatus"] = False
                item["serviceOperMessage"] = self.format_local_err_msg(local_status_msg)

            return False

    def showrunningconfiginterface(self, pes):  # noqa: ignore=C901
        """
                Method for Pre-check to validate show running interface <local_port>

                Args:
                    pes: list containing the json o/p from dial

                Returns:
                    status: True or False

                Raises:
                    Exception

        """
        logger.info(f"Entering showrunningconfiginterface validation for {pes.get('peName')}")
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show running interface <local_port>"
        expected_resp = f"No sub-interface and Aggregation(bundle) configuration associated with the Interface used"
        logger.info(
            f"showrunningconfiginterface command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showRunningConfigInterface')}"
        )
        try:
            status = True
            # bug fix 3108 (Create ES fails in pre-check with inappropriate error message
            # when physical interface is already associated with the bundle-ether)
            if pes["showRunningConfigInterface"]["rpc-reply"]["data"]:
                interfaces_run = pes["showRunningConfigInterface"]["rpc-reply"]["data"]["interfaces"]["interface"]
                interface_running_list = []
                # the interface should not have any configuration present so listing the key which should not be present
                unexpected_keys = ["subinterface", "aggregate-id"]
                if isinstance(interfaces_run, dict):
                    interface_running_list = [interfaces_run]
                elif isinstance(interfaces_run, list):
                    interface_running_list = interfaces_run

                # parse through interface list
                for item in interface_running_list:
                    key_item = get_all_keys(item)
                    for itr in unexpected_keys:
                        if itr in key_item:
                            # bug fix 3469, 3564 improving the message format of pre/post check validation
                            # bug fix 3108 (Create ES fails in pre-check with inappropriate error message
                            # when physical interface is already associated with the bundle-ether)
                            actual_resp = f"{itr} association already exists on Interface = {item['name']}"
                            local_status_msg = self.format_message(
                                device_name=device_name,
                                cmd_name=cmd_name,
                                expected_response=expected_resp,
                                actual_response=actual_resp,
                            )
                            self.validation_msg += local_status_msg
                            logger.error(local_status_msg)
                            status = False
            logger.info(f"Exiting showrunningconfiginterface after validation for {pes.get('peName')}")
            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)
            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)
            return False

    def showlldpneighbors(self, pes, model, stage="post"):  # noqa: ignore=C901
        """
                combined method for Pre-check and Post-check to validate show LLDP neighbor

                Args:
                    pes: list containing the json o/p from dial
                    model: database model or the hydrated model
                    stage: check during pre or post check

                Returns:
                    status: True or False

                Raises:
                    Exception

        """
        logger.info(f"Entering showlldpneighbors validation for {pes.get('peName')}")
        status = True
        flag = "hostname-not-matched"
        expected_lldp = {}
        logger.info(
            f"showlldpneighbors command output from DIAL for {pes.get('peName')} " f"as {pes.get('showLldpNeighbors')}"
        )

        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show LLDP neighbor <local_port>"

        try:
            # get the olt name from service model
            olt_name = model["service"]["ceHostname"]
            logger.debug(f"OLT Name is {olt_name}")

            # bug fix for 2937
            if pes["showLldpNeighbors"]["rpc-reply"]["data"] is None:
                for pes_in_db in model["service"]["pes"]:
                    if pes_in_db["hostname"] == pes["peName"]:
                        local_ports = nested_lookup(key="localPort", document=pes_in_db)
                        # bug fix 3469, 3564 improving the message format of pre/post check validation
                        actual_resp = f"Interface {local_ports} is not available"
                        expected_resp = f"Interface {local_ports} should be available in device"
                        local_status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )
                        self.validation_msg += local_status_msg
                        return False

            # collect data from user model
            remote_port_name_usermodel = []
            local_port_name_usermodel = []

            for pes_in_db in model["service"]["pes"]:
                if pes_in_db["hostname"] == pes["peName"]:
                    flag = "hostname-matched"
                    remote_port_name_usermodel = nested_lookup(key="remotePort", document=pes_in_db)
                    local_port_name_usermodel = nested_lookup(key="localPort", document=pes_in_db)
                    for val in range(0, len(local_port_name_usermodel)):
                        expected_lldp[local_port_name_usermodel[val]] = remote_port_name_usermodel[val]

                    break

            if flag != "hostname-matched":
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"device {pes['peName']} is not present in usermodel"
                expected_resp = f"device name from pre/post o/p should match with usermodel"
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += local_status_msg
                logger.error(local_status_msg)
                return False

            # check and convert dict to list
            interfaces = pes["showLldpNeighbors"]["rpc-reply"]["data"]["lldp"]["interfaces"]["interface"]
            interface_list = []
            interface_name = []
            if isinstance(interfaces, dict):
                interface_list = [interfaces]
            elif isinstance(interfaces, list):
                interface_list = interfaces

            for item in interface_list:
                interface_name.append(item["name"])

            # If the Interface is not exisitng (incorrect interface)
            for intf in local_port_name_usermodel:
                if intf not in interface_name:
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = f"Interface {intf} is not present in device"
                    expected_resp = f"Interface {intf} should be a valid interface of device"
                    local_status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    self.validation_msg += local_status_msg
                    # fix for bug 3177
                    if self.es_db_model is not None:
                        for item in self.es_db_model["service"]["pes"]:
                            if item["hostname"] == pes["peName"]:
                                for port in item["ports"]:
                                    if port["localPort"] == intf:
                                        port["linkOperStatus"] = False
                                        port["linkOperMessage"] += local_status_msg

                    return False

            for itr in interface_list:
                if itr.get("neighbors") is None:
                    if stage == "pre":
                        logger.debug("neighbhor can be none in precheck stage")
                        continue
                    else:
                        actual_resp = f"no neighbhor found for interface {itr['name']}"
                        expected_resp = f"neighbhor should be available"
                        local_status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )

                        self.validation_msg += local_status_msg
                        logger.error(local_status_msg)

                        # fix for bug 3177
                        if self.es_db_model is not None:
                            for item in self.es_db_model["service"]["pes"]:
                                if item["hostname"] == pes["peName"]:
                                    for port in item["ports"]:
                                        if port["localPort"] == itr["name"]:
                                            port["linkOperStatus"] = False
                                            port["linkOperMessage"] += local_status_msg

                        return False
                else:
                    # check olt id
                    actual_resp = f"olt connected is {itr['neighbors']['neighbor']['id']} for {itr['name']} "
                    expected_resp = f"olt connected should be {olt_name}"
                    local_status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    if itr["neighbors"]["neighbor"]["id"] != olt_name:
                        self.validation_msg += local_status_msg
                        logger.error(local_status_msg)

                        # fix for bug 3177
                        if self.es_db_model is not None:
                            for item in self.es_db_model["service"]["pes"]:
                                if item["hostname"] == pes["peName"]:
                                    for port in item["ports"]:
                                        if port["localPort"] == itr["name"]:
                                            port["linkOperStatus"] = False
                                            port["linkOperMessage"] += local_status_msg

                        return False
                    else:
                        logger.debug(local_status_msg)
                    # check for remote port
                    remote_port = itr["neighbors"]["neighbor"]["state"]["port-id"]
                    actual_resp = f"remote interface of {itr['name']} is {remote_port}"
                    expected_resp = f"remote interface of {itr['name']} should be {expected_lldp[itr['name']]}"
                    local_status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )
                    if remote_port != expected_lldp[itr["name"]]:
                        self.validation_msg += local_status_msg

                        logger.error(local_status_msg)

                        if self.es_db_model is not None:
                            for item in self.es_db_model["service"]["pes"]:
                                if item["hostname"] == pes["peName"]:
                                    for port in item["ports"]:
                                        if port["localPort"] == itr["name"]:
                                            port["linkOperStatus"] = False
                                            port["linkOperMessage"] += local_status_msg

                        return False
                    else:
                        logger.debug(local_status_msg)
            logger.info(f"Exiting showlldpneighbors after validation for {pes.get('peName')}")
            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"lldp neighbhor can be None for Precheck or have the ports towards the OLT "
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)

            # fix for bug 3177
            if self.es_db_model is not None:
                for item in self.es_db_model["service"]["pes"]:
                    if item["hostname"] == pes["peName"]:
                        for port in item["ports"]:
                            port["linkOperStatus"] = False
                            port["linkOperMessage"] += local_status_msg

            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"lldp neighbhor can be None for Precheck or have the ports towards the OLT "
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += local_status_msg
            logger.error(local_status_msg)

            # fix for bug 3177
            if self.es_db_model is not None:
                for item in self.es_db_model["service"]["pes"]:
                    if item["hostname"] == pes["peName"]:
                        for port in item["ports"]:
                            port["linkOperStatus"] = False
                            port["linkOperMessage"] += local_status_msg

            return False

    def showinterfaceoperational(self, pes, model, svlan_list=None):  # noqa: ignore=C901,W503
        """
        Method validate show interface <interface-name> detail along with MTU

        Args:
            pes: list containing the json o/p from dial
            model: database model or the hydrated model
            svlan_list : list of svlan  incase of subscriber EVPN

        Returns:
            status: True or False

        Raises:
            Exception


        """
        logger.info(f"Entering showinterfaceoperational validation for {pes.get('peName')}")
        logger.info(
            f"showinterfaceoperational command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showInterfaceOperational')}"
        )
        status = True
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show interface <interface-name>"

        try:
            # get admin_status of all interface in the o/p
            admin_status = nested_lookup(key="admin-status", document=pes["showInterfaceOperational"])
            # get oper status for all interface in the o/p
            oper_status = nested_lookup(key="oper-status", document=pes["showInterfaceOperational"])
            # get interface name in the o/p
            interface_list = nested_lookup(key="name", document=pes["showInterfaceOperational"])

            # make interface list unique as the interface_list contains duplicate name
            unique_interface_list = []
            for intf in interface_list:
                if intf not in unique_interface_list:
                    unique_interface_list.append(intf)
            # bug Fix for 3087
            if svlan_list is not None:
                svlan_exists = False
                for unique_intf in unique_interface_list:
                    for svlan_itr in svlan_list:
                        vlan_string = "." + svlan_itr
                        if vlan_string in unique_intf:
                            svlan_exists = True
                            actual_resp = f"Interface {unique_intf} is already configured"
                            expected_resp = f"Interface {unique_intf} should not be pre configured"
                            local_status_msg = self.format_message(
                                device_name=device_name,
                                cmd_name=cmd_name,
                                expected_response=expected_resp,
                                actual_response=actual_resp,
                            )

                            self.validation_msg += local_status_msg
                            logger.error(local_status_msg)
                            return False

                # for tA devices model is None
                if model is None:
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = f"sub-interface in TA device is not already configured"
                    expected_resp = f"sub-interface in TA device should not be pre configured"
                    local_status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )
                    logger.debug(local_status_msg)
                    return True
                if svlan_exists is False:
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = f"sub-interface in MA device is not already configured"
                    expected_resp = f"sub-interface in MA device should not be pre configured"
                    local_status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )
                    logger.debug(local_status_msg)

            for state in range(0, len(admin_status)):
                if admin_status[state] != "UP" or oper_status[state] != "UP":  # noqa: W503  # noqa: W503
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = f"admin_state={admin_status[state]} and oper_state={oper_status[state]} "
                    expected_resp = f"admin_state=UP and oper_state=UP "
                    local_status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )
                    logger.error(local_status_msg)
                    self.validation_msg += local_status_msg
                    status = False
                    # update the Model locally
                    if self.es_db_model is not None:
                        for item in self.es_db_model["service"]["pes"]:
                            if item["hostname"] == pes["peName"]:
                                for port in item["ports"]:
                                    if port["localPort"] == unique_interface_list[state]:
                                        port["linkOperStatus"] = False
                                        port["linkOperMessage"] += local_status_msg

            if status is False:
                return status

            configured_mtu = nested_lookup(key="mtu", document=pes["showInterfaceOperational"])

            if len(configured_mtu) == 0:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"no mtu field found"
                expected_resp = f"mtu field should not be empty"
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

                self.validation_msg += local_status_msg
                logger.error(local_status_msg)
                return False
            count = 0
            for item in configured_mtu:

                mtulist = [str(model["service"]["mtu"]), str(model["service"]["mtu"] + 4)]

                if item not in mtulist:
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = f"mtu is {item}"
                    expected_resp = f"{mtulist}"
                    local_status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )
                    logger.error(local_status_msg)
                    self.validation_msg += local_status_msg
                    if self.es_db_model is not None:
                        for item_itr in self.es_db_model["service"]["pes"]:
                            if item_itr["hostname"] == pes["peName"]:
                                for port in item_itr["ports"]:
                                    if port["localPort"] == unique_interface_list[count]:
                                        port["linkOperStatus"] = False
                                        port["linkOperMessage"] += local_status_msg

                    # return False
                    status = False
                count += 1

            if status is False:
                return status
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"admin and oper status in up state"
            expected_resp = f"admin and oper status should be up state"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            logger.debug(local_status_msg)
            logger.info(f"Exiting showinterfaceoperational after validation for {pes.get('peName')}")
            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"admin and oper status should be up state"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            logger.error(local_status_msg)
            self.validation_msg += local_status_msg

            # fix for bug 3177
            if self.es_db_model is not None:
                for item in self.es_db_model["service"]["pes"]:
                    if item["hostname"] == pes["peName"]:
                        for port in item["ports"]:
                            port["linkOperStatus"] = False
                            port["linkOperMessage"] += local_status_msg

            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"admin and oper status should be up state"
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            logger.error(local_status_msg)
            self.validation_msg += local_status_msg

            # fix for bug 3177
            if self.es_db_model is not None:
                for item in self.es_db_model["service"]["pes"]:
                    if item["hostname"] == pes["peName"]:
                        for port in item["ports"]:
                            port["linkOperStatus"] = False
                            port["linkOperMessage"] += local_status_msg

            return False

    def showbundleinfo(self, pes, db_model, ta_devices=[]):  # noqa: ignore=C901
        """
        Method for show bundle bundle-ether <lag_id>
        Args:
            pes : list containing the o/p of commands
            db_model : db/user/service model
            ta_devices : device list for TA
        Returns:
            status: "PASS" or "FAIL"
        Raises:
            Exception
        """
        logger.info(f"Entering showbundleinfo validation for {pes.get('peName')}")
        logger.info(
            f"showbundleinfo command output from DIAL for {pes.get('peName')} " f"as {pes.get('showBundleInfo')}"
        )
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show bundle bundle-ether <lag_id>"
        try:

            # show bundle bundle-ether lagid
            bundle_status = nested_lookup(key="oper-status", document=pes["showBundleInfo"])
            if len(bundle_status) != 0:
                # fix for bug 3177
                for bund in bundle_status:
                    if bund != "UP":
                        # bug fix 3469, 3564 improving the message format of pre/post check validation
                        actual_resp = f"bundle(lag) is down"
                        expected_resp = f"bundle(lag) should be up"
                        status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )
                        logger.error(status_msg)
                        self.validation_msg += status_msg
                        if self.es_db_model is not None:
                            for item in self.es_db_model["service"]["pes"]:
                                if item["hostname"] == pes["peName"]:
                                    item["lagOperStatus"] = False
                                    item["lagOperMessage"] = status_msg
                        return False
            else:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"oper-status field is missing in command o/p"
                expected_resp = f"oper-status field should be present in command o/p"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

                logger.error(status_msg)
                self.validation_msg += status_msg
                if self.es_db_model is not None:
                    for item in self.es_db_model["service"]["pes"]:
                        if item["hostname"] == pes["peName"]:
                            item["lagOperStatus"] = False
                            item["lagOperMessage"] = status_msg

                return False

            members_from_lag = nested_lookup(key="member", document=pes["showBundleInfo"])
            members_from_lag_arranged = []
            for item in members_from_lag:
                if isinstance(item, list):
                    for sub_item in item:
                        members_from_lag_arranged.append(sub_item)
                else:
                    members_from_lag_arranged.append(item)
            if len(members_from_lag_arranged) == 0:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"member field is missing in command o/p"
                expected_resp = f"member field should be present in command o/p"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

                logger.error(status_msg)
                self.validation_msg += status_msg

                if self.es_db_model is not None:
                    for item in self.es_db_model["service"]["pes"]:
                        if item["hostname"] == pes["peName"]:
                            item["lagOperStatus"] = False
                            item["lagOperMessage"] = status_msg

                return False

            if pes["peName"] not in ta_devices:

                local_port_name_usermodel = []
                for pes_in_db in db_model["service"]["pes"]:
                    if pes_in_db["hostname"] == pes["peName"]:
                        local_port_name_usermodel = nested_lookup(key="localPort", document=pes_in_db)
                        break

                if len(members_from_lag_arranged) != len(local_port_name_usermodel):
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = f"members={members_from_lag_arranged}"
                    expected_resp = f"members={local_port_name_usermodel}"
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    self.validation_msg += status_msg
                    logger.error(status_msg)

                    if self.es_db_model is not None:
                        for item in self.es_db_model["service"]["pes"]:
                            if item["hostname"] == pes["peName"]:
                                item["lagOperStatus"] = False
                                item["lagOperMessage"] = status_msg

                    return False

                for item in members_from_lag_arranged:
                    if item not in local_port_name_usermodel:
                        # bug fix 3469, 3564 improving the message format of pre/post check validation
                        actual_resp = f"interface {item} is lag member"
                        expected_resp = f"only members={local_port_name_usermodel} as per user Model"
                        status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )

                        self.validation_msg += status_msg
                        logger.error(status_msg)
                        if self.es_db_model is not None:
                            for item_itr in self.es_db_model["service"]["pes"]:
                                if item_itr["hostname"] == pes["peName"]:
                                    item_itr["lagOperStatus"] = False
                                    item_itr["lagOperMessage"] = status_msg

                        return False
            logger.info(f"Exiting showbundleinfo after validation for {pes.get('peName')}")
            return True
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"bundle should be up with correct lag member interfaces"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += status_msg
            logger.error(status_msg)
            if self.es_db_model is not None:
                for item in self.es_db_model["service"]["pes"]:
                    if item["hostname"] == pes["peName"]:
                        item["lagOperStatus"] = False
                        item["lagOperMessage"] = status_msg

            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"bundle should be up with correct lag member interfaces"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += status_msg
            logger.error(status_msg)
            if self.es_db_model is not None:
                for item in self.es_db_model["service"]["pes"]:
                    if item["hostname"] == pes["peName"]:
                        item["lagOperStatus"] = False
                        item["lagOperMessage"] = status_msg

            return False

    def get_bundle_name(self, pes, model, svlan=None):  # noqa: ignore=C901
        """
        api to get the bundle name

        Args:
            pes: list containing the json o/p from dial
            svlan : svlan optional
            model : user/db/service model

        Returns:
            status: "PASS" or "FAIL", bundle_interface name

        Raises:
            Exception

        """
        status = True

        # find the required value

        try:
            lagid = ""
            for pes_item in model["service"]["pes"]:
                if pes_item["hostname"] == pes["peName"]:
                    lagid = pes_item["lagId"]
                    break

            if lagid == "":
                status_msg = f"getbundleName : operation failed for PE = {pes['peName']}"
                logger.error(status_msg)
                return False

            interface_name = "Bundle-Ether" + str(lagid)
            if svlan is not None:
                interface_name += "." + str(svlan)
            return status, interface_name

        except Exception as err:
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(err)
            logger.error("\n" + str(ex_info[1]))
            logger.error("\n" + traceback.extract_tb(tb).__str__())
            status_msg = f"Unable to get the Bundle Id from the service to PE: = {pes['peName']} "
            logger.error(status_msg)
            return False

    def showevpngroup(self, pes, model):  # noqa: ignore=C901
        """
        Method for show evpn group <group_id>
        Args:
            pes : list containing the o/p of commands
            model : db/service/user model
        Returns:
            status: True or False
        Raises:
            Exception
        """
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        logger.info(f"Entering showevpngroup validation for {pes.get('peName')}")
        logger.info(
            f"showevpngroup command output from DIAL for {pes.get('peName')} " f"as {pes.get('showEvpnGroupInfo')}"
        )
        device_name = pes["peName"]
        cmd_name = "show evpn group <group_id>"
        try:
            status = True
            bundle_available = False
            # Get teh list of access interfaces
            get_bundle_intf_name = self.get_bundle_name(pes=pes, model=model)
            if get_bundle_intf_name[0] is False:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"Unable to get bundle id"
                expected_resp = f"bundle id should be retrieved"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                logger.error(status_msg)
                self.validation_msg += status_msg
                if self.es_db_model is not None:
                    item = self.es_db_model["service"]
                    item["serviceOperStatus"] = False
                    item["serviceOperMessage"] = self.format_local_err_msg(status_msg)

                return False

            interface_name = get_bundle_intf_name[1]
            interfaces = nested_lookup(key="access-interface", document=pes["showEvpnGroupInfo"])
            interfaces = interfaces[0]
            interface_list = []
            if isinstance(interfaces, dict):
                interface_list = [interfaces]
            elif isinstance(interfaces, list):
                interface_list = interfaces
            if len(interface_list) == 0:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"access-interface is empty"
                expected_resp = f"access-interface data should be present in the o/p"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

                self.validation_msg += status_msg
                logger.error(status_msg)
                if self.es_db_model is not None:
                    item = self.es_db_model["service"]
                    item["serviceOperStatus"] = False
                    item["serviceOperMessage"] = self.format_local_err_msg(status_msg)

                return False

            for idx in range(len(interface_list)):
                if interface_list[idx]["interface-name"] == interface_name:
                    if interface_list[idx]["state"] == "im-state-up":
                        bundle_available = True
                        status = True
                    else:
                        # bug fix 3469, 3564 improving the message format of pre/post check validation
                        actual_resp = f"{interface_name} is down state"
                        expected_resp = f"{interface_name} should be up state"
                        status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )
                        logger.error(status_msg)
                        self.validation_msg += status_msg
                        status = False
                        if self.es_db_model is not None:
                            item = self.es_db_model["service"]
                            item["serviceOperStatus"] = False
                            item["serviceOperMessage"] = self.format_local_err_msg(status_msg)
                    break

            if not bundle_available:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"{interface_name} is not configured under evpn group"
                expected_resp = f"{interface_name} should be configured under evpn group"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

                logger.error(status_msg)
                self.validation_msg += status_msg
                status = False
                if self.es_db_model is not None:
                    item = self.es_db_model["service"]
                    item["serviceOperStatus"] = False
                    item["serviceOperMessage"] = self.format_local_err_msg(status_msg)
            logger.info(f"Exiting showevpngroup after validation for {pes.get('peName')}")
            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"evpn group should contain lag with operstatus as up"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg
            if self.es_db_model is not None:
                item = self.es_db_model["service"]
                item["serviceOperStatus"] = False
                item["serviceOperMessage"] = self.format_local_err_msg(status_msg)

            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"evpn group should contain lag with operstatus as up"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg
            if self.es_db_model is not None:
                item = self.es_db_model["service"]
                item["serviceOperStatus"] = False
                item["serviceOperMessage"] = self.format_local_err_msg(status_msg)

            return False

    # Bug fix for 3165
    def showevpnethernetsegment(self, pes, stage="pre", iplist=[], op_msg=None):  # noqa: ignore=C901,W503
        """
        Method for show evpn ethernet-segment esi <esi_value> detail or
            show evpn ethernet-segment interface <interface-name> detail
        Args:
            pes : list containing the o/p of commands
            stage: check in pre or post check
            iplist: dict of ip adddress
            op_msg: None or Error message
        Returns:
            status: True or False
        Raises:
            Exception
        """
        logger.info(f"Entering showevpnethernetsegment validation for {pes.get('peName')}")
        logger.info(
            f"showevpnethernetsegment command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showEvpnEthernetSegmentEsi')}"
        )
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show evpn ethernet-segment esi <esi_value> detail"

        try:
            status = True
            esi_type = nested_lookup(key="esi-type", document=pes["showEvpnEthernetSegmentEsi"])
            load_balance = nested_lookup(key="load-balance-mode-config", document=pes["showEvpnEthernetSegmentEsi"])
            ebgp_gates = nested_lookup(key="es-bgp-gates", document=pes["showEvpnEthernetSegmentEsi"])
            l2fib_gates = nested_lookup(key="es-l2fib-gates", document=pes["showEvpnEthernetSegmentEsi"])

            if len(esi_type) == 0 or len(load_balance) == 0 or len(ebgp_gates) == 0:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"esi-type/load-balance-mode-config/es-bgp-gates field is missing in cmd o/p"
                expected_resp = f"esi-type/load-balance-mode-config/es-bgp-gates field should be in cmd o/p"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += status_msg
                logger.error(status_msg)
                return False

            if stage == "pre":
                status = True

            else:
                for itr in range(0, len(esi_type)):
                    if (
                        esi_type[itr] != "esi-type1"
                        or load_balance[itr] != "multi-homed-aa-per-flow"  # noqa: W503
                        or ebgp_gates[itr] != "Ready"  # noqa: W503
                        or l2fib_gates[itr] != "Ready"  # noqa: W503
                    ):
                        actual_resp = (
                            f"esi_type={esi_type[itr]} load_balance={load_balance[itr]} "
                            f"ebgp_gates={ebgp_gates[itr]} l2fib_gates = {l2fib_gates[itr]} "
                        )
                        expected_resp = (
                            f"esi_type=esi-type1 load_balance=multi-homed-aa-per-flow] egbp_gates=Ready "
                            f"l2fib_gates=Ready"
                        )
                        local_status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )

                        logger.error(local_status_msg)
                        self.validation_msg += local_status_msg
                        return False

                    # if the Device in TA no need for nexthop list check
                    for item in iplist:
                        if item == "TA_DEVICE":
                            # bug fix 3469, 3564 improving the message format of pre/post check validation
                            actual_resp = f"skipping Net hop check for TA devices"
                            expected_resp = f"Next hop check should be skipped for TA device"
                            local_status_msg = self.format_message(
                                device_name=device_name,
                                cmd_name=cmd_name,
                                expected_response=expected_resp,
                                actual_response=actual_resp,
                            )

                            logger.debug(local_status_msg)
                            return True

                    # the device is MA so look for nexthop
                    if op_msg is not None:
                        actual_resp = f"{op_msg}"
                        expected_resp = f"loopback address should be available"
                        local_status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )

                        self.validation_msg += local_status_msg
                        logger.error(local_status_msg)
                        return False

                    next_hop_list = nested_lookup(
                        key="next-hop",
                        document=pes["showEvpnEthernetSegmentEsi"]["rpc-reply"]["data"]["evpn"]["active"][
                            "ethernet-segments"
                        ]["ethernet-segment"]["next-hop"],
                    )

                    flag = False
                    temp_nexthoplist = ",".join([str(item) for item in next_hop_list])
                    temp_iplist = ",".join([str(item) for item in iplist])
                    # bug fix 3165
                    ips = re.findall(r"\d*[.]\d*[.]\d*[.]\d*", temp_nexthoplist)
                    if len(ips) == 0:
                        ips = temp_nexthoplist

                    if len(next_hop_list) != len(iplist):
                        # bug fix 3469, 3564 improving the message format of pre/post check validation
                        actual_resp = f"nexthops={ips}"
                        expected_resp = f"nexthops={temp_iplist}"
                        local_status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )

                        self.validation_msg += local_status_msg
                        logger.error(local_status_msg)
                        return False
                    # changes for bug 3754
                    if set(ips) == set(iplist):
                        flag = True
                    else:
                        flag = False
                    if flag:
                        # bug fix 3469, 3564 improving the message format of pre/post check validation
                        actual_resp = f"nexthops={ips}"
                        expected_resp = f"nexthops={temp_iplist}"
                        local_status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )

                        logger.debug(local_status_msg)
                        status = True
                    else:
                        actual_resp = f"nexthops={ips}"
                        expected_resp = f"nexthops={temp_iplist}"
                        local_status_msg = self.format_message(
                            device_name=device_name,
                            cmd_name=cmd_name,
                            expected_response=expected_resp,
                            actual_response=actual_resp,
                        )
                        logger.error(local_status_msg)
                        self.validation_msg += local_status_msg

                        return False
            logger.info(f"Exiting showevpnethernetsegment after validation for {pes.get('peName')}")
            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = (
                f"esi-type == esi-type1 es-bgp-gates == Ready es-l2fib-gates == Ready "
                f"load-balance-mode-oper == multi-homed-aa-per-flow the number of elements in next-hop "
                f"list should be "
                f"equal to the number of MAs in the service order and their IP address should match with "
                f"loopback0"
            )
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            self.validation_msg += local_status_msg
            logger.error(local_status_msg)

            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = (
                f"esi-type == esi-type1 es-bgp-gates == Ready es-l2fib-gates == Ready "
                f"load-balance-mode-oper == multi-homed-aa-per-flow the number of elements in next-hop "
                f"list should be "
                f"equal to the number of MAs in the service order and their IP address should match with "
                f"loopback0"
            )
            local_status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            self.validation_msg += local_status_msg
            logger.error(local_status_msg)

            return False

    def show_policmap_policyname(self, pes, model, service="management"):  # noqa: ignore=C901
        """
        Method for show policy-map policy-name <pmap-name> or
            show policy-map policy-name
            Verify the both  ingress and Egress Policy are configured
        Args:
            pes : list containing the o/p of commands
            model : user/db/service model
            service: Management or subscriber
        Returns:
            status: True or false

        Raises:
            Exception

        """
        logger.info(f"Entering show_policmap_policyname validation for {pes.get('peName')}")
        logger.info(
            f"show_policmap_policyname command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showPolicyMapPmapName')}"
        )
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show policy-map policy-name <pmap-name>"
        expected_resp = "ingress and egress policy Map should be existing"

        try:
            service_ingress_policy = None
            service_egress_policy = None

            configured_policy_map_list = nested_lookup(key="policy-map-name", document=pes["showPolicyMapPmapName"])

            if service == "management":
                service_ingress_policy = model["service"]["ingressQos"]
                service_egress_policy = model["service"]["egressQos"]

            if service == "subscriber":
                # find the Qos policy map from the hydrated model
                for ma_item in model["service"]["pes"]["ma"]:
                    if ma_item["hostname"] == pes["peName"]:
                        service_ingress_policy = ma_item["ingressQos"]
                        service_egress_policy = ma_item["egressQos"]
                        break

            if service_egress_policy is None and service_ingress_policy is None:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"failed to fetch the policy map from model"
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += local_status_msg
                logger.error(local_status_msg)
                return False

            expected_resp = (
                f"{service_ingress_policy} and {service_egress_policy} policyMap should be configured in " f"router"
            )

            if len(configured_policy_map_list) < 2:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"policy map={configured_policy_map_list} check for empty dial o/p"
                local_status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += local_status_msg
                return False
            if service_ingress_policy not in configured_policy_map_list:
                actual_resp = f"{service_ingress_policy} not in configured"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                logger.error(status_msg)
                self.validation_msg += status_msg
                return False

            if service_egress_policy not in configured_policy_map_list:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"{service_egress_policy} not in configured"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

                logger.error(status_msg)
                self.validation_msg += status_msg
                return False
            logger.info(f"Exiting show_policmap_policyname after validation for {pes.get('peName')}")
            return True
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg
            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg
            return False

    def verify_l2vpn_service(self, parsed_cli_output, netconf_key, expected_value):  # noqa: ignore=C901
        """
        Verify the l2vpn service to different Data
        Args:
            parsed_cli_output:
            expected_value:
            netconf_key:

        Returns: True or False

        """
        try:
            attribute_value = nested_lookup(netconf_key, parsed_cli_output)
            self.l2vpn_service_attribute = attribute_value
            if len(attribute_value) == 0:
                logger.error(f"{netconf_key} is not present in output")
                return False

            for item in attribute_value:
                if item == expected_value:
                    return True

            logger.error(f"expected value is = {expected_value} for netconf_key ")

            return False

        except Exception as err:
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.debug(err)
            logger.debug("\n" + str(ex_info[1]))
            logger.debug("\n" + traceback.extract_tb(tb).__str__())
            status_msg = f"VerifyL2vpnAcValidation is failed "
            logger.error(status_msg)
            return False

    def verify_l2vpn_ac_service(self, parsed_cli_output, netconf_key, expected_value):  # noqa: ignore=C901
        """
        Verify the l2vpn service to different Data
        Args:
            parsed_cli_output:
            expected_value:
            netconf_key:

        Returns: True/False

        """
        try:
            attachment_circuits = nested_lookup("bridge-ac", parsed_cli_output)
            if len(attachment_circuits) == 0:
                logger.error(f"bridge-ac is not found in output")
                return False

            attribute_value = nested_lookup(netconf_key, attachment_circuits)
            self.l2vpn_ac_service_attribute = attribute_value
            if len(attribute_value) == 0:
                logger.error(f"{netconf_key} is not present in output")
                return False
            for item in attribute_value:
                if item == expected_value:
                    return True

            logger.error(f"expected value is {expected_value} for netconf_key ")
            return False
        except Exception as err:
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.debug(err)
            logger.debug("\n" + str(ex_info[1]))
            logger.debug("\n" + traceback.extract_tb(tb).__str__())
            status_msg = f"VerifyL2vpnAcValidation is failed "
            logger.debug(status_msg)
            return False

    def show_l2vpn_bridge_domain(self, pes, model, es_model, service="management"):  # noqa: ignore=C901
        """
        Method for show l2vpn bridge-domain bd-name <evi-number> detail or
            Verify the both  Bridge domain status

        Args:
            pes : list containing the o/p of commands
            model : user/service/db model
            es_model : ethernet segment DB model
            service: management or subscriber

        Returns:
            status: True or False

        Raises:
            Exception
        """
        logger.info(f"Entering show_l2vpn_bridge_domain validation for {pes.get('peName')}")
        logger.info(
            f"show_l2vpn_bridge_domain command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showL2vpnBridgeDomainBdName')}"
        )
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show l2vpn bridge-domain bd-name <evi-number> detail"

        try:
            evi_number = str(model["service"]["eviNumber"])
            svlan = ""

            l2vpn_service = {}
            interface_list = []

            if service == "management":
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                l2vpn_service.update(
                    group_name=[
                        "bridge-domain-group-name",
                        model["service"]["bridgeGroup"],
                        "bridge domain group name is incorrect",
                    ]
                )
                svlan = model["service"]["svlan"]

            if service == "subscriber":
                # find the bridge domain
                hostname_flag = False
                for ma_item in model["service"]["pes"]["ma"]:
                    if ma_item["hostname"] == pes["peName"]:
                        hostname_flag = True
                        l2vpn_service.update(
                            group_name=[
                                "bridge-domain-group-name",
                                ma_item["ceHostname"].replace(".", "_"),
                                "bridge domain group name is incorrect",
                            ]
                        )
                        svlan = ma_item["svlan"]
                        break
                # Bug fix 3164
                if hostname_flag is False:
                    for ta_item in model["service"]["pes"]["ta"]:
                        for ta_data in ta_item:
                            if ta_data["hostname"] == pes["peName"]:
                                svlan = ta_data["svlan"]
                                lag = "Bundle-Ether" + str(ta_data["lagId"]) + "." + str(svlan)
                                interface_list.append(lag)

            if len(interface_list) == 0:
                bundle_name = self.get_bundle_name(pes=pes, model=es_model, svlan=svlan)
                interface_list.append(bundle_name[1])

            for intf_item in interface_list:
                l2vpn_service[intf_item] = ["interface-name", intf_item, "sub interface is incorrect"]

            l2vpn_service.update(bridgedomain_name=["bridge-domain-name", evi_number, "bridge domain id is incorrect"],)

            for attribute, values in l2vpn_service.items():
                if self.verify_l2vpn_service(pes["showL2vpnBridgeDomainBdName"], values[0], values[1]) is False:
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = f"{values[2]}" + f":{self.l2vpn_service_attribute}"
                    expected_resp = f"{values[1]}"
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    logger.error(status_msg)
                    self.validation_msg += status_msg
                    return False

            # Verify AC state
            attach_compare = {}
            # Dictionary is created as "Netconf -key, Expected, failed message"
            # Bug Fix 3760 - Corrected serviceOperMessage by adding details of AC which is down
            attach_compare.update(
                state=["state", "l2vpn-segment-state-up", "AC State is not UP"],
                maclimit=["mac-limit", str(model["service"]["macLimit"]), "Mac-limit is incorrect"],
                maclimitaction=["mac-limit-action", "limit-no-flood", "Mac limit action is incorrect"],
                maclimitnotification=[
                    "mac-limit-notification",
                    "mac-limit-notify-syslog-trap",
                    "Mac Limit Notification is incorrect",
                ],
                unicast_storm_control_pps=[
                    "unicast-storm-control-pps",
                    str(model["service"]["stormControl"]["unknownUnicast"]),
                    "Unicast Storm Control is incorrect",
                ],
                multicast_storm_control_pps=[
                    "multicast-storm-control-pps",
                    str(model["service"]["stormControl"]["multicast"]),
                    "Unicast Storm Control is incorrect",
                ],
                broadcast_storm_control_pps=[
                    "broadcast-storm-control-pps",
                    str(model["service"]["stormControl"]["broadcast"]),
                    "Broadcast Storm Control is incorrect",
                ],
                # upper_vlan=["upper", model["service"]["mtu"], "Outer Vlan"],
            )

            for attribute, values in attach_compare.items():
                if self.verify_l2vpn_ac_service(pes["showL2vpnBridgeDomainBdName"], values[0], values[1]) is False:
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    # Bug Fix 3760 - Corrected serviceOperMessage by adding details of AC which is down
                    actual_resp = f"{values[2]}" + f" for {bundle_name[1]}"
                    expected_resp = f"AC State should be UP"
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    logger.error(status_msg)
                    self.validation_msg += status_msg
                    return False
            logger.info(f"Exiting show_l2vpn_bridge_domain after validation for {pes.get('peName')}")
            return True
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"l2vpn bridge domain exists with policy attributes"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg
            return False

        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"l2vpn bridge domain exists with policy attributes"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg
            return False

    def show_evpn_evi_bd(self, pes, model, stage="post"):  # noqa: ignore=C901
        """
        Method for show evpn evi bridge-domain <evi-number> detail

        Args:
            pes : list containing the o/p of commands
            model: Db/user/service model
            stage: pre or post check

        Returns:
            status: True or False

        Raises:
            Exception

        """
        logger.info(f"Entering show_evpn_evi_bd validation for {pes.get('peName')}")
        logger.info(
            f"show_evpn_evi_bd command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showEvpnEviBridgeDomain')}"
        )
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show evpn evi bridge-domain <evi-number> detail"

        try:
            # bug fix 3103
            bd_name_list = nested_lookup("bd-name", pes["showEvpnEviBridgeDomain"])
            evi_value = str(model["service"]["eviNumber"])

            if stage == "pre":
                if evi_value in bd_name_list:
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = f"bridge domain={evi_value} is present"
                    expected_resp = f"In pre check stage bridge domain={evi_value} should not be in evpn instance "
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    self.validation_msg += status_msg
                    logger.error(status_msg)
                    return False
                else:
                    actual_resp = f"bridge domain={evi_value} is not present"
                    expected_resp = f"In pre check stage bridge domain={evi_value} should not be in evpn instance "
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    logger.debug(status_msg)
                    return True
            else:
                if evi_value not in bd_name_list:
                    actual_resp = f"bridge domain={evi_value} is not present"
                    expected_resp = f"In post check stage bridge domain={evi_value} should be in evpn instance "
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    self.validation_msg += status_msg
                    logger.error(status_msg)
                    return False

            mac_advertise = nested_lookup("advertise-mac", pes["showEvpnEviBridgeDomain"])[0]

            if mac_advertise != "true":
                actual_resp = f"mac advertise is not set as true"
                expected_resp = f"mac advertise should be set as true"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )

                self.validation_msg += status_msg
                logger.error(status_msg)
                return False
            logger.info(f"Exiting show_evpn_evi_bd after validation for {pes.get('peName')}")
            return True
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"mac advertise should be set as true with correct bridge domain"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg + ", "
            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"mac advertise should be set as true with correct bridge domain"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg + ", "
            return False

    def check_target(self, pes, policy, egress_ingress, es_model, svlan, bundle_name=None):  # noqa: ignore=C901
        """
        Method to verify the target are available in policy map
        Args:
            pes: pes
            egress_ingress: str: input/out
            policy:
            es_model

        Returns: True or False
        :param pes:
        :param policy:
        :param egress_ingress:
        :param es_model:
        :param svlan:

        """
        try:
            configured_policy_map_list = 0
            configured_policy_map = nested_lookup(key="policy-map-target", document=pes["showPolicyMapTarget"])
            # policy map target of qos type is at index 0
            configured_policy_map = configured_policy_map[0]
            if isinstance(configured_policy_map, dict):
                configured_policy_map_list = [configured_policy_map]
            elif isinstance(configured_policy_map, list):
                configured_policy_map_list = configured_policy_map
            if len(configured_policy_map_list) == 0:
                status_msg = f"show_policmap_targets_policyname:PE = {pes['peName']} failed to get PolicyMapTarget"
                logger.error(status_msg)
                # self.validation_msg += status_msg + ", "
                return False

            if bundle_name is None:
                check_target_intf = self.get_bundle_name(pes=pes, model=es_model, svlan=svlan)
                check_target_intf = check_target_intf[1]
            else:
                check_target_intf = bundle_name + "." + str(svlan)

            for each_policy in configured_policy_map_list:
                pmap_name = nested_lookup("policy-map-name", each_policy)
                target_intf = nested_lookup("targets", each_policy)
                if policy == pmap_name[0]:

                    if re.search(check_target_intf + r"\s+" + egress_ingress, str(target_intf[0])):
                        logger.debug(f"expected = {check_target_intf + ' ' + egress_ingress} in {str(target_intf[0])}")
                        return True

            return False
        except Exception as err:
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.debug(err)
            logger.debug("\n" + str(ex_info[1]))
            logger.debug("\n" + traceback.extract_tb(tb).__str__())
            status_msg = f"showPolicyMapTarget: Validation operation failed for PE = {pes['peName']} "
            logger.error(status_msg)
            # self.validation_msg += status_msg + ", "
            return False

    def show_policmap_targets_policyname(self, pes, model, es_model, service="management"):  # noqa: ignore=C901
        """
        Method for show policy-map targets policy-name <pmap-name> or
            show policy-map targets policy-name
            Verify the both  ingress and Egress Policy are configured

        Args:
            pes : list containing the o/p of commands
            model: Sevice/db model
            es_model: ethernet segement model
            service: subscriber or management

        Returns:
            status: True or False

        Raises:
            Exception
        """
        logger.info(f"Entering show_policmap_targets_policyname validation for {pes.get('peName')}")
        logger.info(
            f"show_policmap_targets_policyname command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showPolicyMapTarget')}"
        )
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show policy-map targets policy-name <pmap-name>"

        # Bug fix for 3164
        try:
            service_ingress_policy_list = []
            service_egress_policy_list = []
            svlan_list = []
            interface_list = []
            state = []

            if service == "management":
                service_ingress_policy_list.append(model["service"]["ingressQos"])
                service_egress_policy_list.append(model["service"]["egressQos"])
                svlan_list.append(model["service"]["svlan"])

            if service == "subscriber":
                hostname_flag = False
                # find the Qos policy map from the hydrated model
                for ma_item in model["service"]["pes"]["ma"]:
                    if ma_item["hostname"] == pes["peName"]:
                        hostname_flag = True
                        service_ingress_policy_list.append(ma_item["ingressQos"])
                        service_egress_policy_list.append(ma_item["egressQos"])
                        svlan_list.append(ma_item["svlan"])
                        break
                # Routine for TA , incase pe["pename"] matches TA
                if hostname_flag is False:
                    for ta_item in model["service"]["pes"]["ta"]:
                        for ta_data in ta_item:
                            if ta_data["hostname"] == pes["peName"]:
                                service_ingress_policy_list.append(ta_data["ingressQos"])
                                service_egress_policy_list.append(ta_data["egressQos"])
                                svlan_list.append(ta_data["svlan"])
                                lag = "Bundle-Ether" + str(ta_data["lagId"])
                                interface_list.append(lag)

            if len(service_egress_policy_list) == 0 or len(service_ingress_policy_list) == 0:
                # bug fix 3469, 3564 improving the message format of pre/post check validation
                actual_resp = f"failed to fetch the ingress and egress policy map from model"
                expected_resp = f"ingress and egress policy map extracted from model"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += status_msg

                return False

            # loop to the list and check for policy map target
            for itr in range(0, len(service_ingress_policy_list)):

                if len(interface_list) == 0:
                    interface = None
                else:
                    interface = interface_list[itr]

                if (
                    self.check_target(
                        pes=pes,
                        policy=service_ingress_policy_list[itr],
                        egress_ingress="input",
                        es_model=es_model,
                        svlan=svlan_list[itr],
                        bundle_name=interface,
                    )
                    is False
                ):
                    actual_resp = (
                        f"policy {service_ingress_policy_list[itr]} is not applied to bundle "
                        f"sub interface {svlan_list[itr]}"
                    )
                    expected_resp = (
                        f"policy {service_ingress_policy_list[itr]} applied to bundle "
                        f"sub interface {svlan_list[itr]}"
                    )
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    logger.error(status_msg)
                    self.validation_msg += status_msg
                    state.append(False)
                else:
                    # bug fix 3469, 3564 improving the message format of pre/post check validation
                    actual_resp = (
                        f"policy {service_ingress_policy_list[itr]} is applied to bundle "
                        f"sub interface {svlan_list[itr]}"
                    )
                    expected_resp = (
                        f"policy {service_ingress_policy_list[itr]} applied to bundle "
                        f"sub interface {svlan_list[itr]}"
                    )
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )

                    logger.debug(status_msg)

            for itr in range(0, len(service_egress_policy_list)):

                if len(interface_list) == 0:
                    interface = None
                else:
                    interface = interface_list[itr]

                if (
                    self.check_target(
                        pes=pes,
                        policy=service_egress_policy_list[itr],
                        egress_ingress="output",
                        es_model=es_model,
                        svlan=svlan_list[itr],
                        bundle_name=interface,
                    )
                    is False
                ):
                    actual_resp = (
                        f"policy {service_egress_policy_list[itr]} is not applied to bundle "
                        f"sub interface {svlan_list[itr]}"
                    )
                    expected_resp = (
                        f"policy {service_egress_policy_list[itr]} applied to bundle "
                        f"sub interface {svlan_list[itr]}"
                    )
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )
                    logger.error(status_msg)
                    self.validation_msg += status_msg
                    state.append(False)
                else:
                    actual_resp = (
                        f"policy {service_egress_policy_list[itr]} is applied to bundle "
                        f"sub interface {svlan_list[itr]}"
                    )
                    expected_resp = (
                        f"policy {service_egress_policy_list[itr]} applied to bundle "
                        f"sub interface {svlan_list[itr]}"
                    )
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )
                    logger.debug(status_msg)
                # fix for 3378[ to check if service_egress_policy and service_ingress_policy both are present]
                for val in state:
                    if val is False:
                        return False
            logger.info(f"Exiting show_policmap_targets_policyname after validation for {pes.get('peName')}")
            return True
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"Policies in model should be configured on interface"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg
            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            expected_resp = f"Policies in model should be configured on interface"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )

            logger.error(status_msg)
            self.validation_msg += status_msg
            return False

    def precheck_showbundleinfo(self, pes, model):
        """
        combined method for Pre-check to validate show bundle bundle-ether <lag_id>

        Args:
            pes: list containing the json o/p from dial
            model: database model or the hydrated model

        Returns:
            status: True or false

        Raises:
            Exception

        """
        logger.info(f"Entering precheck_showbundleinfo validation for {pes.get('peName')}")
        status = True
        # bug fix 3469, 3564 improving the message format of pre/post check validation
        device_name = pes["peName"]
        cmd_name = "show bundle bundle-ether <lag_id>"
        expected_resp = f"bundle interface should not exists during pre check stage"
        logger.info(
            f"precheck_showbundleinfo command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showBundleInfo')}"
        )

        # find the required value

        try:

            lagid = ""
            for pes_item in model["service"]["pes"]:
                if pes_item["hostname"] == pes["peName"]:
                    lagid = pes_item["lagId"]
                    break

            if lagid == "":
                actual_resp = f"lag id not fetched from model"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += status_msg
                logger.error(status_msg)

                return False

            interface_name = "Bundle-Ether" + str(lagid)
            lag_name_dial = nested_lookup(key="name", document=pes["showBundleInfo"])
            if interface_name in lag_name_dial:
                actual_resp = f"bundle(lag) {interface_name} is already configured"
                status_msg = self.format_message(
                    device_name=device_name,
                    cmd_name=cmd_name,
                    expected_response=expected_resp,
                    actual_response=actual_resp,
                )
                self.validation_msg += status_msg
                logger.error(status_msg)

                return False
            logger.info(f"Exiting precheck_showbundleinfo after validation for {pes.get('peName')}")
            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += status_msg
            logger.error(status_msg)

            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += status_msg
            logger.error(status_msg)

            return False

    def showbundleinfodetail(self, pes, stage="pre"):  # noqa: ignore=C901
        """
        validate show bundle bundle-ether <lag_id> detail lacp check

        Args:
            pes: list containing the json o/p from dial
            stage

        Returns:
            status: True or false

        Raises:
            Exception

        """
        logger.info(f"Entering showbundleinfodetail validation for {pes.get('peName')}")
        status = True
        device_name = pes["peName"]
        cmd_name = "show bundle bundle-ether <lag_id> detail"
        expected_resp = f"lacp should be true and active in all member interface"
        logger.info(
            f"showbundleinfodetail command output from DIAL for {pes.get('peName')} "
            f"as {pes.get('showBundleDetail')}"
        )

        try:
            bundle_bundle = pes["showBundleDetail"]["rpc-reply"]["data"]["bundles"]["bundles"]["bundle"]
            bundle_list = self.generic_utils.convert_list(bundle_bundle)
            for bund in bundle_list:
                bundle_name = bund["bundle-interface"]
                bundle_member = bund["members"]["member"]
                bund_member_list = self.generic_utils.convert_list(bundle_member)
                for bund_intf in bund_member_list:
                    bund_intf_name = bund_intf["interface-name"]
                    lacp_flag = bund_intf["lacp-enabled"]
                    member_state = bund_intf["member-mux-data"]["member-state"]
                    actual_resp = f"{bundle_name} interface = {bund_intf_name} lcap = {lacp_flag} state ={member_state}"
                    status_msg = self.format_message(
                        device_name=device_name,
                        cmd_name=cmd_name,
                        expected_response=expected_resp,
                        actual_response=actual_resp,
                    )
                    if lacp_flag == "TRUE" and member_state == "bmd-mbr-state-active":
                        logger.debug(status_msg)

                    else:
                        logger.error(status_msg)
                        self.validation_msg += status_msg
                        # update the Model locally
                        if self.es_db_model is not None:
                            for item in self.es_db_model["service"]["pes"]:
                                if item["hostname"] == pes["peName"]:
                                    for port in item["ports"]:
                                        if port["localPort"] == bund_intf_name:
                                            port["linkOperStatus"] = False
                                            port["linkOperMessage"] += status_msg

                        return False
            logger.info(f"Exiting showbundleinfodetail after validation for {pes.get('peName')}")
            return status
        except (KeyError, AttributeError, ValueError) as err:
            logger.error(f"{err.args[0]} occurred while processing {cmd_name}")
            # bug fix 3469, 3564 improving the message format of pre/post check validation
            actual_resp = f"Command output could be empty or Exception raised"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += status_msg
            logger.error(status_msg)
            return False
        except Exception as err:
            logger.debug(err)
            ex_info = sys.exc_info()
            tb = ex_info[2]
            logger.error(f"{str(ex_info[1])} in {traceback.extract_tb(tb).__str__()}")
            # bug fix 3469, 3564 improving the message format of pre/post check validationon
            actual_resp = f"Command output could be empty or Exception raised"
            status_msg = self.format_message(
                device_name=device_name, cmd_name=cmd_name, expected_response=expected_resp, actual_response=actual_resp
            )
            self.validation_msg += status_msg
            logger.error(status_msg)
            return False
