import argparse
import json
import datetime
from jinja2 import Template
import urllib.parse


def create_es_url(search_name):
    base_url = 'https://splunk-es.sec.corp.zoom.us/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit?search='
    return base_url + urllib.parse.quote(search_name)


def file_to_json(input_file):
    json_file = open(input_file, 'r')
    lines = json_file.readlines()
    data_list = []

    for line in lines:
        data = json.loads(line)
        data_list.append(data['result'])

    return data_list


def json_to_md(json_content):

    sorted_json_content = sorted(
        json_content, key=lambda k: k['action.correlationsearch.label'])

    mdresult = ''

    md_template = '## {{ name }}\n'
    md_template += '[{{ title }}]({{ url }})\n'
    md_template += '### Description\n{{ description }}\n'
    md_template += '### Search\n```\n{{ search }}\n```\n'
    md_template += '- **Earliest time:** {{ earliest }}\n'
    md_template += '- **Latest time:** {{ latest }}\n'
    md_template += '- **Cron:** {{ cron }}\n'
    md_template += '- **Notable Title:** {{ n_title }}\n'
    md_template += '- **Notable Description:** {{ n_desc }}\n'
    md_template += '- **Notable Security Domain:** {{ n_domain }}\n'
    md_template += '- **Notable Severity:** {{ n_severity }}\n\n'
    template = Template(md_template)

    for item in sorted_json_content:
        md = template.render(
            name=item['action.correlationsearch.label'],
            url=create_es_url(item['title']),
            title=item['title'],
            description=item['description'],
            search=item['search'],
            earliest=item['dispatch.earliest_time'],
            latest=item['dispatch.latest_time'],
            cron=item['cron_schedule'],
            n_title=item['action.notable.param.rule_title'],
            n_desc=item['action.notable.param.rule_description'],
            n_domain=item['action.notable.param.security_domain'],
            n_severity=item['action.notable.param.severity']
        )
        mdresult += md
    return mdresult


def json_to_md_last7(json_content):
    today = datetime.datetime.today()
    week_ago = today - datetime.timedelta(days=7)

    mdresult = ''

    md_template = '## {{ updated }} - {{ name }}\n'
    md_template += '[{{ title }}]({{ url }})\n'
    md_template += '### Description\n{{ description }}\n'
    md_template += '### Search\n```\n{{ search }}\n```\n\n'
    template = Template(md_template)

    for item in json_content:
        if 'updated_time' in item.keys():
            if datetime.datetime.fromtimestamp(int(item['updated_time'])) > week_ago:
                md = template.render(
                    name=item['action.correlationsearch.label'],
                    updated=item['updated'],
                    url=create_es_url(item['title']),
                    title=item['title'],
                    description=item['description'],
                    search=item['search'])
                mdresult += md
            else:
                pass
        else:
            pass

    return mdresult


def write_output(output_file, md):
    with open(output_file, 'w') as output_file:
        print(md, file=output_file)


def main():
    json_content = file_to_json('input/correlation_searches.json')
    md_content = json_to_md(json_content)
    write_output('docs/correlation_searches.md', md_content)
    md_content_last7 = json_to_md_last7(json_content)
    write_output('docs/correlation_searches_recent.md', md_content_last7)


'''
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", type=str, help="Specify input JSON file.")
parser.add_argument("-o", "--output", type=str, help="Specify the output file")
args = parser.parse_args()
'''

if __name__ == "__main__":
    main()
