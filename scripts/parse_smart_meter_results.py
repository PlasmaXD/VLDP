import csv
import os
import sys

PROTOCOL_NAMES = ["base", "expand", "shuffle"]

HEADERS = ["Day", "Estimate"]

if __name__ == "__main__":
    datetime = sys.argv[1]

    input_file_directory = "./results/raw/smart_meter/"
    output_file_directory = "./results/parsed/smart_meter/"
    if not os.path.exists(output_file_directory):
        os.makedirs(output_file_directory)

    for protocol_name in PROTOCOL_NAMES:
        file_name = f"{datetime}_smart_meter_{protocol_name}"
        input_file_name = f"{input_file_directory}{file_name}.txt"
        output_file_name = f"{output_file_directory}{file_name}.csv"
        results_per_day_all = []
        with open(input_file_name, 'r') as input_file:
            results_for_one_day = []
            day_found = False
            for line in input_file.readlines():
                if HEADERS[0] in line:
                    day_text = line.split(' ')[-1].rstrip()[:-1]
                    results_for_one_day.append(day_text)
                elif HEADERS[1] in line:
                    estimate_text = line.split(": ")[-1].rstrip()
                    estimate_text = str(round(float(estimate_text), 6))
                    results_for_one_day.append(estimate_text)
                    results_per_day_all.append(results_for_one_day)
                    results_for_one_day = []

        with open(output_file_name, 'w', newline='') as output_file:
            writer = csv.writer(output_file)
            writer.writerow(HEADERS)
            writer.writerows(results_per_day_all)
