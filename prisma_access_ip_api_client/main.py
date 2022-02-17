
import logging
import argparse
import os
import sys

from .logger import logger
from .PrismaAccessIPApi import PrismaAccessIPApi

def main():
    """This is the Main function of the package.
    It is also used as entry point during pip installation
    """
    global context
    parser = argparse.ArgumentParser()
    # https://docs.paloaltonetworks.com/prisma/prisma-access/prisma-access-panorama-admin/prisma-access-overview/prisma-access-infrastructure-ip-addresses/run-the-api-script-used-to-retrieve-ip-addresses
    parser.add_argument(
        "-k", "--key", help="API Key")
    parser.add_argument('-s', '--service-type', choices=[
                        "all", "remote_network", "gp_gateway", "gp_portal", "clean_pipe", "swg_proxy"],  default="all", help='Service Type')
    parser.add_argument('-a', '--address-type', choices=[
                        "all", "active", "reserved", "service_ip", "auth_cache_service", "network_load_balancer"], default="all",  help='Address Type')
    parser.add_argument('-c', '--action-type', choices=[
                        "pre_allocate"],  default=None, help='Action Type. Only for Mobile Users.')
    parser.add_argument('-l', '--location', choices=[
                        "all", "deployed"], default="all", help='Location')
    parser.add_argument("-v", "--verbose", help="Verbose output", action='store_true')
    parser.add_argument('-f', '--format', choices=[
                        "csv", "json", "xml"], default="json", help='Output Format')
    parser.add_argument('-o', '--output', help='Output File (By default writes to terminal)')            
    parser.add_argument('-i', '--ignore-ssl-warnings', action='store_true', help='Ignore SSL Warnings. NOT RECOMMENDED. ONLY USE WITH CAUTION')    
    parser.add_argument('-e', '--env', default="prod", help='Env for URL: api.{env}.datapath.prismaaccess.com. Default = prod')   
    parser.add_argument('--silent', action='store_true', help='Suppress logging (Except for error)')   
    args = parser.parse_args()

    if args.action_type is not None and args.service_type != "gp_gateway":
        parser.error(
            'Action-Type is only valid for service-type gp_gateway')
    if args.key is None:
        if 'PRISMA_API_KEY' in os.environ:
            API_KEY = os.environ["PRISMA_API_KEY"]
        else:
            logger.error("Please provide API Key via -k argument of by setting PRISMA_API_KEY env variable")
            sys.exit(-1)
    else:
        API_KEY = args.key
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.silent:
        logger.setLevel(logging.ERROR)
    
    api = PrismaAccessIPApi(API_KEY)
    resp = api.request(args.service_type, args.address_type, args.action_type, args.location, args.ignore_ssl_warnings, args.env)

    if args.format=="json":
        output = resp.as_json()
    elif args.format=="csv":
        output = resp.as_csv()
    elif args.format=="xml":
        output = resp.as_xml()

    logger.info(f"Output: \n\n{output}")
    if args.silent:
        print(output)
    if args.output:
        f = open(args.output, "w")
        f.write(output)
        f.close()

if __name__ == "__main__":
    main()
