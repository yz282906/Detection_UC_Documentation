import argparse
import json
import os
import glob

def delete_files(folder_path):
    files = glob.glob(folder_path + '*')
    for f in files:
        os.remove(f)

def file_to_json(input_file):
    json_file = open(input_file, 'r')
    lines = json_file.readlines()
    data_list = []

    for line in lines:
        data = json.loads(line)
        data_list.append(data['result'])

    sorted_list = sorted(data_list, key=lambda k: k['action.correlationsearch.label'])
    return sorted_list

def write_json_file(output_location, json_content):
    with open(output_location, 'w') as output_file:
        print(json_content, file=output_file)

def main():
    delete_files(args.output)
    json_obj = file_to_json(args.input)
    for item in json_obj:
        write_json_file((args.output + (item['action.correlationsearch.label'].lower().replace(' - ',' ').replace(':','').replace(' ','_') + ".json")), json.dumps(item, indent=1))

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", type=str, help="Specify input JSON file.")
parser.add_argument("-o", "--output", type=str, help="Specify the output folder.")
args = parser.parse_args()

if __name__ == "__main__":
    main()