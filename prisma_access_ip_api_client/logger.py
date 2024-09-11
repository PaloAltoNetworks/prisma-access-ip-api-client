import logging
import sys

logger = logging.getLogger("prisma_access_ip_api")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(module)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)