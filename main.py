from agents.delivery.delivery_agent import DeliveryAgent

# ==========================================================
# AAKCD - Main Integration File
# Each team member's agent will eventually be imported here.
#
# Agents:
# - Reconnaissance Agent
# - Delivery Agent
# - Exploitation Agent
# - Installation Agent
# - Command & Control Agent
# ==========================================================


def main():

    # ------------------------------------------------------
    # DELIVERY AGENT - Francesco
    # ------------------------------------------------------

    delivery_event = {
        "source_ip": "192.168.1.50",
        "attachment": "invoice.exe"
    }

    delivery_agent = DeliveryAgent()
    delivery_alert = delivery_agent.analyse_event(delivery_event)

    if delivery_alert:
        print(delivery_alert.to_dict())
    else:
        print("No suspicious delivery activity detected.")

    # ------------------------------------------------------
    # RECONNAISSANCE AGENT
    # Team member integration goes here
    # ------------------------------------------------------


    # ------------------------------------------------------
    # EXPLOITATION AGENT
    # Team member integration goes here
    # ------------------------------------------------------


    # ------------------------------------------------------
    # INSTALLATION AGENT
    # Team member integration goes here
    # ------------------------------------------------------


    # ------------------------------------------------------
    # COMMAND & CONTROL AGENT
    # Team member integration goes here
    # ------------------------------------------------------


if __name__ == "__main__":
    main()