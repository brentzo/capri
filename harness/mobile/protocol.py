"""Mobile-specific role protocol and virtual target rules."""

MOBILE_TARGET = "mobile-app"
MOBILE_TOOL = "mobile"
MOBILE_PORT_HINT = "mobile uses 0"


def validate_role_port(port):
    if port != 0:
        return "port_range", "mobile requests use the virtual port 0"
    return None


ROLE_PORT_VALIDATORS = {MOBILE_TOOL: validate_role_port}


