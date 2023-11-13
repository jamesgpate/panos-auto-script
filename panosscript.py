"""Automating the palo alto vlans"""
import sys
import csv

from panos.firewall import Firewall
from panos.network import Layer3Subinterface
from panos.objects import AddressObject
from panos.policies import Rulebase, SecurityRule

from login_details import HOSTNAME,USERNAME,PASSWORD

def open_a_csv(csv_input: str):
    """Opens a CSV and returns a dictionary

    Args:
        csv_input (str): The filename

    Returns:
        input_data: The CSV as a dictionary, with the first row as the dictionary keys
    """
    input_data = []
    with open(csv_input, encoding="utf-8") as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        for row in csv_reader:
            input_data.append(row)
    return input_data

def init():
    """Initializes the firewall

    Returns:
        firewall: The PA Firewall object
    """
    # Import from the login_details file and log in
    firewall = Firewall(HOSTNAME, api_username=USERNAME, api_password=PASSWORD)
    return firewall

def load_vlans():
    """Loading up the vlans into lists to use

    Returns:
        vlans: the vlan ids
        subnet_sizes: the subnet sizes for the related vlans
    """
    # blank lists to hold them, import from csv in future
    vlans = []
    subnet_sizes = []

    for i in range(101,116):
        vlans.append(i)
        subnet_sizes.append(24)

    for i in range(200,900,100):
        vlans.append(i)
        subnet_sizes.append(24)

    for i in range(1100,1200):
        vlans.append(i)
        subnet_sizes.append(30)
    return (vlans, subnet_sizes)

def create_rule(ip_address: str, vlan: int):
    """Create the firewall rule

    Args:
        ip_address (str): ip range of the network
        vlan (int): the vlan number
    """
    new_rule = SecurityRule(
        name=f'VLAN {vlan} block to other vlans',
        fromzone=['guest'],
        tozone=['guest'],
        source=[ip_address],
        destination=[ip_address],
        negate_destination=True,
        application=['any'],
        service=['application-default'],
        action='deny',
        log_end=None
    )
    return new_rule

def create_vlans(vlans: list, subnet_sizes: list, firewall: Firewall):
    """make all of the objects and add them to the firewall

    Args:
        vlans (list): list of vlans
        subnet_sizes (list): subnet sizes for the vlans
    """
    # Loading the rulebase from the firewall
    rulebase = Rulebase()
    firewall.add(rulebase)
    print("Getting the current rules...")
    SecurityRule.refreshall(rulebase)

    # run through the list of vlans
    for i, vlan in enumerate(vlans):
        print(f'Adding VLAN {vlan}')
        gateway = AddressObject(
            name=f'VLAN {vlan} Gateway',
            value=f'10.{vlan//100}.{vlan%100}.1/32',
            type="ip-netmask",
            description=f'The gateway IP address on the Palo for VLAN {vlan} traffic'
        )
        firewall.add(gateway)

        network_range = AddressObject(
            name=f'VLAN {vlan} Network Range',
            value=f'10.{vlan//100}.{vlan%100}.0/{subnet_sizes[i]}',
            type="ip-range",
            description=f'The network range on the Palo for VLAN {vlan}'
        )
        firewall.add(network_range)

        dhcp = AddressObject(
            name=f'VLAN {vlan} DHCP Server',
            value=f'10.{vlan//100}.{vlan%100}.2/32',
            type="ip-netmask",
            description=f'The DHCP Server for VLAN {vlan}'
        )
        firewall.add(dhcp)

        subint = Layer3Subinterface(
            name=f'ethernet1/3.{vlan}',
            tag=vlan,
            ip=f'10.{vlan//100}.{vlan%100}.1/32',
            comment=f'Subinterface for VLAN {vlan}'
        )
        firewall.add(subint)

        rule = create_rule(network_range.name, vlan)
        rulebase.add(rule)

    print("Creating all on the firewall... Please wait...")
    firewall.find(f'VLAN {vlans[0]} Gateway', AddressObject).create_similar()
    firewall.find(f'ethernet1/3.{vlans[0]}', Layer3Subinterface).create_similar()
    firewall.find(f'VLAN {vlans[0]} block to other vlans', SecurityRule).create_similar()

def main():
    """Main function
    """

    print("Initializing the firewall connection...")
    firewall = init()

    print("Loading the vlans...")
    vlans, subnet_sizes = load_vlans()

    print("Creating the vlans...")
    create_vlans(vlans, subnet_sizes, firewall)

    print("Committing to the firewall...")
    firewall.commit(sync=True)

    print("Done!")

if __name__ == "__main__":
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        main()
