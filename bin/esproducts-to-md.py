import argparse
import json
from jinja2 import Template

def file_to_json(input_file):
    json_file = open(input_file, 'r')
    lines = json_file.readlines()
    data_list = []

    for line in lines:
        data = json.loads(line)
        data_list.append(data['result'])

    sorted_list = sorted(data_list, key=lambda k: k['product'])
    return sorted_list


def json_to_md(json_content):
    mdresult = ''

    md_template = '\n## {{ product }}\n'
    md_template += '\n### Description\n'
    md_template += '\n{{ description }}\n'
    md_template += '\n| Security Relevant | Normalized | Criticality |\n'
    md_template += '|-------------------|------------|-------------|\n'
    md_template += '| {{ security_logs }} | {{ normalized }} | {{ criticality }} |\n'
    md_template += '### Indexes\n{% if indexes is iterable and (indexes is not string and indexes is not mapping) %}{% for index in indexes %}- {{ index }}\n{% endfor %}{% else %}- {{ indexes }}\n{% endif %}'
    md_template += '### Sourcetypes\n{% if sourcetype_details is iterable and (sourcetype_details is not string and sourcetype_details is not mapping) %}{% for sourcetype in sourcetype_details %}- {{ sourcetype }}\n{% endfor %}{% else %}- {{ sourcetype_details }}\n{% endif %}'
    template = Template(md_template)

    for item in json_content:
        md = template.render(
            product=item['product'],
            description=item['product_description'], 
            indexes=item['indexes'],
            sourcetype_details=item['sourcetype_details'],
            security_logs=item['security_logs'],
            normalized=item['normalized'],
            criticality=item['criticality']
            )
        mdresult+=md
    return mdresult

def write_output(output_file, md):
    with open(output_file, 'w') as output_file:
        print(md, file=output_file)

def main():
    json_content = file_to_json('input/product_data_sources.json')
    json_content
    md_content = json_to_md(json_content)
    write_output('docs/es_data_sources.md', md_content)

if __name__ == "__main__":
    main()