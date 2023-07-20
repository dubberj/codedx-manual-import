import csv
import argparse
import pandas as pd
from lxml import etree as ET

# Property of Synopsys, Created by John Dubber - Version 2.03
# usage: New_Dic_csv_to_xml.py [-h] -i INPUT -o OUTPUT

# Dictionary mapping CSV column names to XML element names.
# Modify this dictionary to match your CSV column names to the appropriate XML tags. Examples below, make sure to change to match your csv headings.
# If you want to use a fixed value for a specific XML tag, specify the value here by starting with a "$" sign
# Left side is codedx mapping - - Right side csv header or fixed value.
# Please referance codedx manual import documentaion for further description of values below.

column_to_xml_mapping = {
    "REPORT_DATE": "$2023-05-30",
    "REPORT_TOOL": "$My Custom Tool",
    "TOOL_NAME": "Jira-Pentest",
    "FINDING_STATUS": "$new",               # Must use fixed value if you don't have headers with these values "new" "escalated" "ignored" "false-positive" "fixed" "unresolved" "gone" "assigned"
    "NATIVE_ID_VALUE": "Type of Pentest",
    "CWE_ID": "$0",
    "TOOL_CODE": "Key",
    "LOCATION_PATH": "Target",
    "LINE_START": "Lines",
    "LINE_END": "Lines",
    "DESCRIPTION_TEXT": "Risk Rating",
    "METADATA_VALUE_KEY": "$Description",
    "METADATA_VALUE_TEXT": "Summary",
    "SEVERITY": "Ease of Exploitation",     # Must use fixed value if you don't have headers with these values "info" "low" "medium" "high" "critical" "unspecified" or row that matches these types
    "DATE": "$2023-05-30",
    "MY_TOOL_ID": "$My Tool ID",
    "CVE_YEAR": "$",
    "CVE_SEQUENCE": "$",
    "FQDN_TEXT": "$FQDN",
    "TOOL_CATEGORY": "$Security",
    "DESCRIPTION_FORMAT": "$plain-text",
    "INCLUDE_IN_HASH": "$false"
}

# Retrieve mapped value from header row or fixed value from dictionary and add above.

# No need to adjust code below unless for further customisation.

def get_mapped_or_fixed_value(row, key, default=''):
    mapped_or_fixed_value = column_to_xml_mapping.get(key, default)
    return mapped_or_fixed_value[1:] if mapped_or_fixed_value.startswith('$') else row.get(mapped_or_fixed_value, default)

# function definitions...
# Create finding element with attributes

def create_finding_element(_, row):
    finding = ET.Element('finding')
    finding.set('severity', get_mapped_or_fixed_value(row, "SEVERITY"))
    finding.set('date', get_mapped_or_fixed_value(row, "DATE"))
    return finding

# Create native-id sub-element with attributes

def create_native_id_element(finding, row):
    native_id = ET.SubElement(finding, 'native-id')
    native_id.set('name', get_mapped_or_fixed_value(row, "MY_TOOL_ID"))
    native_id.set('value', str(row.get(get_mapped_or_fixed_value(row, "NATIVE_ID_VALUE"), '')))
    return native_id

# Create CWE sub-element with attributes    

def create_cwe_element(finding):
    cwe = ET.SubElement(finding, 'cwe')
    cwe.set('id', get_mapped_or_fixed_value(None, "CWE_ID"))
    return cwe

# Create CVE sub-element with attributes if necessary data is present

def create_cve_element(finding):
    cve_year = get_mapped_or_fixed_value(None, "CVE_YEAR")
    cve_sequence = get_mapped_or_fixed_value(None, "CVE_SEQUENCE")
    if cve_year and cve_sequence:
        cves = ET.SubElement(finding, 'cves')
        cve = ET.SubElement(cves, 'cve')
        cve.set('year', cve_year)
        cve.set('sequence-number', cve_sequence)
        return cve
    else:
        return None

# Create host sub-element with FQDN sub-element and text

def create_host_element(finding):
    host = ET.SubElement(finding, 'host')
    fqdn = ET.SubElement(host, 'fqdn')
    fqdn.text = get_mapped_or_fixed_value(None, "FQDN_TEXT")
    return host

# Create tool sub-element with attributes

def create_tool_element(finding, row):
    tool = ET.SubElement(finding, 'tool')
    tool.set('name', get_mapped_or_fixed_value(row, "TOOL_NAME"))
    tool.set('category', get_mapped_or_fixed_value(row, "TOOL_CATEGORY"))
    tool.set('code', get_mapped_or_fixed_value(row, "TOOL_CODE"))
    return tool

# Create location sub-element with line sub-element and attributes

def create_location_element(finding, row):
    location = ET.SubElement(finding, 'location')
    location.set('path', get_mapped_or_fixed_value(row, "LOCATION_PATH"))
    line = ET.SubElement(location, 'line')
    line_start = row.get('LINE_START')
    line_end = row.get('LINE_END')
    line.set('start', line_start if line_start else '0')
    line.set('end', line_end if line_end else '0')
    return location

# Create description sub-element with attributes and text

def create_description_element(finding, row):
    description = ET.SubElement(finding, 'description')
    description.set('format', get_mapped_or_fixed_value(row, "DESCRIPTION_FORMAT"))
    description.set('include-in-hash', get_mapped_or_fixed_value(row, "INCLUDE_IN_HASH"))
    description.text = get_mapped_or_fixed_value(row, "DESCRIPTION_TEXT")
    return description

# Create metadata sub-element with value sub-element, attribute, and text

def create_metadata_element(finding, row):
    metadata = ET.SubElement(finding, 'metadata')
    value = ET.SubElement(metadata, 'value')
    value.set('key', get_mapped_or_fixed_value(row, "METADATA_VALUE_KEY"))
    value.text = get_mapped_or_fixed_value(row, "METADATA_VALUE_TEXT")
    return metadata

# Process each row in the dataframe and append it to the XML report root

def process_report_row(report_root, row):
    finding = create_finding_element(report_root, row)
    create_native_id_element(finding, row)
    create_cwe_element(finding)
    cve_element = create_cve_element(finding)
    if cve_element is not None:
        finding.append(cve_element)
    create_host_element(finding)
    create_tool_element(finding, row)
    create_location_element(finding, row)
    create_description_element(finding, row)
    create_metadata_element(finding, row)
    report_root.append(finding)

# Convert the input CSV file to an output XML file

def csv_to_xml(input_file, output_file):
    df = pd.read_csv(input_file)
    root = ET.Element('report')
    root.set('date', get_mapped_or_fixed_value(None, "REPORT_DATE"))
    root.set('generator', get_mapped_or_fixed_value(None, "REPORT_TOOL"))
    findings = ET.SubElement(root, 'findings')
    for _, row in df.iterrows():
        process_report_row(findings, row)
    tree = ET.ElementTree(root)
    tree.write(output_file, pretty_print=True, xml_declaration=True, encoding='utf-8')

# Entry point of the script

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert CSV to XML')
    parser.add_argument('-i', '--input', type=str, required=True, help='Input CSV file')
    parser.add_argument('-o', '--output', type=str, required=True, help='Output XML file')
    args = parser.parse_args()

# Parse command-line arguments and execute CSV to XML conversion
    try:
        csv_to_xml(args.input, args.output)
    except FileNotFoundError as fnf_error:
        print(f"Error: {fnf_error}")
    except csv.Error as csv_error:
        print(f"Error: {csv_error}")
    except ET.ParseError as parse_error:
        print(f"Error: {parse_error}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
