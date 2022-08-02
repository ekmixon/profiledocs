#!/usr/bin/env python
# TODO: the recursion is horribad, please fix

import plistlib
import uuid
import os.path
import logging
from optparse import OptionParser

logger = logging.getLogger(__name__)

def generate_payload(data, result):
    """Generate top-level payload keys"""
    result['PayloadType'] = 'Configuration'
    result['PayloadOrganization'] = 'Example Organization'
    result['PayloadUUID'] = str(uuid.uuid4())
    result[
        'PayloadIdentifier'
    ] = f"{data.get('pfm_domain', 'domain.undefined')}.example"

    result['PayloadDisplayName'] = f"Example: {data.get('pfm_title')}"
    result['PayloadDescription'] = f"Example: {data.get('pfm_description')}"
    result['PayloadVersion'] = '1'
    result['PayloadContent'] = [{}]
    generate(data['pfm_subkeys'], result['PayloadContent'][0])


def generate_dict(data, result):
    if 'pfm_version' not in data:
        return
    result['PayloadType'] = 'Configuration'
    result['PayloadOrganization'] = 'Example Organization'
    result['PayloadUUID'] = str(uuid.uuid4())
    result[
        'PayloadIdentifier'
    ] = f"{data.get('pfm_domain', 'domain.undefined')}.example"

    result['PayloadDisplayName'] = f"Example: {data.get('pfm_title')}"
    result['PayloadDescription'] = f"Example: {data.get('pfm_description')}"
    result['PayloadVersion'] = '1'
    result['PayloadContent'] = [{}]

    generate(data['pfm_subkeys'], result['PayloadContent'][0])

def pfm_value(key_type, default=None, range_list=None):
    """Generate an appropriate empty value"""
    if range_list is not None:
        return range_list[0]

    if default is not None:
        return default

    if key_type == "string":
        return ""
    elif key_type == "integer":
        return 0
    elif key_type == "boolean":
        return False
    elif key_type == "dictionary":
        return {}
    elif key_type == "real":
        return 0.0
    elif key_type == "data":
        return "Base64EncodedDataHere=="
    elif key_type == "array":
        return []
    elif key_type == "date":
        return "2013-10-12T06:07:27Z"
    else:
        raise Exception(f"Unhandled type {key_type}")

def generate_list(data, result):
    for item in data:
        if 'pfm_name' in item:  # Probably a dict key
            # print(item['pfm_name'])

            if 'pfm_subkeys' in item:  # has keys
                if item['pfm_type'] == 'array':
                    result[item['pfm_name']] = [{}]
                    generate_list(item['pfm_subkeys'], result[item['pfm_name']][0])
                else:
                    result[item['pfm_name']] = {}
                    generate_dict(item['pfm_subkeys'], result[item['pfm_name']])
            else:
                result[item['pfm_name']] = pfm_value(
                    item.get('pfm_type', 'string'),
                    item.get('pfm_default'),
                    item.get('pfm_range_list'),
                )

def generate_pfm_item(data, result):
    """Generate a plist key/value pair from a pfm item i.e an item in the schema that has at least a pfm_name."""
    logger.debug(f"generating kv pair for property: {data['pfm_name']}")

    if data['pfm_name'] in result:
        raise Exception(f"Already in properties dict: {data['pfm_name']}")

    if 'pfm_subkeys' in data:
        if data.get('pfm_type', None) == 'array':

            # Have to discard the pfm_name in the items sub schema

            item = {}
            generate(data['pfm_subkeys'][0], item)
            name, value = item.items()[0]

            result[data['pfm_name']] = [value]
        else:
            result[data['pfm_name']] = {}
            generate(data['pfm_subkeys'], result[data['pfm_name']])
    else:
        result[data['pfm_name']] = pfm_value(
            data['pfm_type'], data.get('pfm_default', None), data.get('pfm_range_list', None))


def generate(data, result):
    """Generate a JSON Schema object as a dict from a parsed plist manifest given as a dict"""
    logger.debug("generate()")

    if isinstance(data, dict):
        if 'pfm_name' in data:
            logging.debug(f"generate pfm dict: {data['pfm_name']}")
            return generate_pfm_item(data, result)
        elif 'pfm_version' in data:  # probably top level dict
            logging.debug("generate pfm header")
            generate_payload(data, result)
        else:
            logger.debug("generate non pfm dict")
    elif isinstance(data, list):
        logger.debug("generating list")
        for item in data:
            generate(item, result)
    else:
        logger.debug("unhandled type")

    return None


if __name__ == "__main__":
    usage = "usage: %prog [options] manifest.plist"
    parser = OptionParser(usage=usage)
    parser.add_option("-o", "--output", dest="output",
                      help="write template to output dir", metavar="DIR")

    (options, args) = parser.parse_args()

    ch = logging.StreamHandler()
    logger.addHandler(ch)
    logger.setLevel(logging.DEBUG)

    plist = plistlib.readPlist(args[-1])
    domain = plist['pfm_domain']

    result = {}
    generate(plist, result)

    if options.output:
        plistlib.writePlist(
            result, os.path.join(options.output, f'{domain}.mobileconfig')
        )

    else:
        from pprint import pprint
        pprint(result)


