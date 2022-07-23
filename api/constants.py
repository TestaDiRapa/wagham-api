import configparser
import datetime
import os

CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static/secret/config.ini"))
EXPIRATION = datetime.timedelta(hours=1)
TIER_REWARDS = {
    1: 15,
    2: 30,
    3: 100,
    4: 500,
    5: 1000
}
ROLE_MAP = {
    "699175663009267732": "I Cavalieri di Malto",
    "704974771376488459": "Master 3",
    "704974466525954178": "Master 2",
    "699240480373997589": "Master 1",
    "757896706472935465": "Delegato di Gilda",
    "699241511098908814": "Gildano",
    "880481772066971658": "Aspirante Gildano"
}