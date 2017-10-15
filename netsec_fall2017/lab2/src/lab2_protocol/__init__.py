import playground
from .lab2a import *

myPeepConnector = playground.Connector(protocolStack=(
    PeepClientFactory(),
    PeepServerFactory()))

playground.setConnector("lab2_protocol", myPeepConnector)
playground.setConnector("my_team_lab2_protocol", myPeepConnector)
