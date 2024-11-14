import csv
import os
import sys

PROTOCOL_NAMES = ["base", "expand", "shuffle"]
N_BINS = 8

if __name__ == "__main__":
    datetime = sys.argv[1]

    input_file_directory = "./results/raw/geo_data/"
    output_file_directory = "./results/parsed/geo_data/"
    if not os.path.exists(output_file_directory):
        os.makedirs(output_file_directory)

    for protocol_name in PROTOCOL_NAMES:
        file_name = f"{datetime}_geo_data_{protocol_name}"
        input_file_name = f"{input_file_directory}{file_name}.txt"
        output_file_name = f"{output_file_directory}{file_name}.csv"

        # first determine the bins
        with open(input_file_name, 'r') as input_file:
            bins = list(set([line.split(": ")[0].rstrip() for line in input_file.readlines() if ": " in line]))

        # then parse the results
        results_per_day_all = []
        with open(input_file_name, 'r') as input_file:
            results_for_one_day = ["" for _ in range(len(bins) + 1)]
            day_found = False
            for line in input_file.readlines():
                if "Day" in line:
                    day_found = True
                    day_text = line.split(' ')[-1].rstrip()[:-1]
                    results_for_one_day[0] = day_text
                elif line.rstrip() == '0' and day_found:
                    results_per_day_all.append(results_for_one_day)
                    results_for_one_day = ["" for _ in range(len(bins) + 1)]
                else:
                    for i, bin_name in enumerate(bins):
                        if bin_name in line:
                            bin_count_text = line.split(": ")[-1].rstrip()
                            results_for_one_day[i + 1] = bin_count_text
                            break

        results_per_day_all.append(results_for_one_day)

        with open(output_file_name, 'w', newline='') as output_file:
            writer = csv.writer(output_file)
            writer.writerow(["Day"] + bins)
            writer.writerows(results_per_day_all)
