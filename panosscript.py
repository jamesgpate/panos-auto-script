"""Import for command line and csv lib"""
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
    firewall = Firewall(HOSTNAME, api_username=USERNAME, api_password=PASSWORD)
    return firewall

def load_vlans():
    """Loading up the vlans into lists to use

    Returns:
        vlans: the vlan ids
        subnet_sizes: the subnet sizes for the related vlans
    """

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

def create_rule(firewall: Firewall):
    """Create the firewall rule

    Args:
        firewall (object): the firewall object
    """
    total_rules_obj = firewall.add(Rulebase())

    new_rule = SecurityRule(
        name='',
        fromzone=['any'],
        tozone=['any'],
        source=['any'],
        destination=['any'],
        application=['any'],
        service=['application-default'],
        action='allow',
        log_end=True
    )
    total_rules_obj.add(new_rule)
    new_rule.create()

def create_vlans_and_commit(vlans: list, subnet_sizes: list, firewall: Firewall):
    """make all of the objects and commit them to the firewall

    Args:
        vlans (list): _description_
        subnet_sizes (list): _description_
    """
    for i, vlan in enumerate(vlans):
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
        gateway.create()
        network_range.create()
        dhcp.create()
        subint.create()

def main():
    """Main function
    """
    firewall = init()
    vlans, subnet_sizes = load_vlans()
    create_vlans_and_commit(vlans, subnet_sizes, firewall)

if __name__ == "__main__":
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        main()
