import json
from pytradfri import Gateway
from pytradfri.api.libcoap_api import APIFactory
from pytradfri.error import PytradfriError
from pytradfri.util import load_json, save_json

from uuid import uuid4
import logging
from pprint import pprint

class light_controller:
    def __init__(self, conf):

        logger = logging.getLogger(__name__)

        logger.setLevel(logging.INFO)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        self.Logger = logger

        hubconf = load_json("tradfri.conf")

        with open(conf) as f:
            config = json.load(f)

        self.hub_gateway = config['hub_gateway']
        self.hub_secret = config['hub_securitycode']

        if not hubconf:
            self.Logger.info("Empty .conf file")

            randid = uuid4().hex

            api_factory = APIFactory(host=self.hub_gateway, psk_id=randid)

            psk = api_factory.generate_psk(self.hub_secret)

            self.Logger.info("Generated new psk: %s"%psk)

            save_json('tradfri.conf',{
                self.hub_gateway:{
                    'identity': randid,
                    'key': psk
                }
            })

            self.api = api_factory.request

        else:
            identity = hubconf[self.hub_gateway].get('identity')
            psk = hubconf[self.hub_gateway].get('key')
            api_factory = APIFactory(host=self.hub_gateway, psk_id=identity, psk=psk)

            self.api = api_factory.request

        self.gateway = Gateway()

        self.refresh_devices()

    def refresh_devices(self):
        devices_c = self.gateway.get_devices()

        dev_cs = self.api(devices_c)

        self.devices = self.api(devices_c)

        self.lights = [d for d in self.devices if d.has_light_control]

        self.Logger.info("Found %s devices."%len(self.devices))
        self.Logger.info("Found %s lights."%len(self.lights))


    def register_light_observer(self, light):
        pass

if __name__ == "__main__":
    lc = light_controller("./config.json")