
from .logger import logger
import json
import logging
import requests
import xmltodict
import sys
from xml.dom import minidom



API_ENDPOINT = "https://api.{env}.datapath.prismaaccess.com/getPrismaAccessIP/v2"


class PrismaAccessIPApiResult():
    """This class gets the result from API Request and parse it. 
    It also allows to export result as csv, xml, or json
    """
    def __init__(self, req_result):
        """PrismaAccessIPApiResult Constructor

        Args:
            req_result (Object): Raw response object from request.post
        """
        self.raw_response = req_result
        self.status_code = req_result.status_code
        self.ok = req_result.ok
        self.json = req_result.json()
        
        if self.status_code >= 400:
            logger.error(f"Response code: {self.status_code}")
            logger.error(f"Response Data: {req_result.text}")
            sys.exit(-1)
        else:
            logger.debug(f"Response code: {self.status_code}")
            logger.debug(f"Response Data: {req_result.text}")
        self.status = self.json["status"]

    def as_json(self):
        """Returns the IP Addresses as JSON.
        The JSON is the raw JSON From the API Response.

        Returns:
            str: Indented JSON
        """
        return json.dumps(self.json, indent=4)

    def as_csv(self):
        """Returns the IP Addresses as CSV.
        Both zones subnets and addresses are included in the CSV.
        You can filter one or the other via entry-type column.

        Returns:
            str: CSV Values
        """
        r = ["Zone, service-type, entry-type, address, address-type, node_name, create_time, allow_listed"]
        for result in self.json["result"]:
            for add_detail in result["address_details"]:
                r.append(
                    ",".join([
                        result["zone"],
                        add_detail["serviceType"],
                        "address_detail",
                        add_detail["address"],
                        add_detail["addressType"],
                        " / ".join(add_detail['node_name']) if 'node_name' in add_detail else "",
                        str(add_detail['create_time']) if 'create_time' in add_detail else "",
                        str(add_detail['allow_listed']) if 'allow_listed' in add_detail else "",
                    ])
                ) 
                for subnet in result["zone_subnet"]:
                    r.append(
                    ",".join([
                        result["zone"],
                        "N/A",
                        "zone_subnet",
                        subnet,
                        "N/A",
                        "N/A",
                        "N/A",
                        "N/A",
                    ])
                ) 
        return "\n".join(r)

    def as_xml(self):
        """Returns the IP Addresses as XML.

        Returns:
            str: Indented XML Version of API response
        """
        json_to_xml = xmltodict.unparse({"data": self.json})
        json_to_xml = minidom.parseString(json_to_xml).toprettyxml(indent="   ")
        return json_to_xml


class PrismaAccessIPApi():
    """The Prisma Access IP API Class

    """

    def __init__(self, key):
        """PrismaAccessIPApi Constructor

        Args:
            key (str): Prisma API Key
        """
        self.key = key

    def request(self, service_type="all", address_type="all", action_type=None, location="all", ignore_ssl_warnings=False, env="prod"):
        """Make Request to API

        Args:
            service_type (str, optional): _description_. Defaults to "all".
            address_type (str, optional): _description_. Defaults to "all".
            action_type (_type_, optional): _description_. Defaults to None.
            location (_type_, optional): _description_. Defaults to None.
        Returns:
            result (PrismaAccessIPApiResult): Request Result
        """
        if service_type not in ["all", "remote_network", "gp_gateway", "gp_portal", "clean_pipe", "swg_proxy"]:
            logger.error(f"{service_type} is not a valid service-type")
            raise ValueError(f"{service_type} is not a valid service-type")
        if address_type not in ["all", "active", "reserved", "service_ip", "auth_cache_service", "network_load_balancer"]:
            logger.error(f"{address_type} is not a valid address-type")
            raise ValueError(f"{address_type} is not a valid address-type")
        if action_type is not None and service_type != "gp_gateway":
            logger.error(
                "Action-Type is only valid for service-type gp_gateway")
            raise ValueError(
                "Action-Type is only valid for service-type gp_gateway")
        headers = {
            "header-api-key": self.key,
        }

        data = {
            "serviceType": service_type,
            "addrType": address_type,
        }
        if action_type is not None:
            data["actionType"] = action_type
        if location is not None:
            data["location"] = location
        url = API_ENDPOINT.format(env=env)
        logger.debug(
            f"Making request to {url} with headers = '{headers}' and data = '{data}'")
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        if ignore_ssl_warnings:
            import urllib3
            urllib3.disable_warnings()
            r = requests.post(url=url, headers=headers,
                          json=data, verify=False)
        else:
            r = requests.post(url=url, headers=headers, json=data)
        logger.debug(str(r.request))

        return PrismaAccessIPApiResult(r)
