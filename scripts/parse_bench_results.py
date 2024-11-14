import csv
import os.path
import re
import sys
import pandas

PROTOCOL_NAMES = ["base_histogram", "expand_histogram", "shuffle_histogram", "base_real", "expand_real", "shuffle_real"]

MEASUREMENT_STEPS = [
    # ZKP statistics
    "Number of constraints",
    "Proving key size",
    "Verifying key size",
    # "Generate randomness" start
    "Client generation",
    "Server generation",
    "Client verification",
    "Generate randomness",  # end
    "Trusted environment computation",
    # "Verifiable randomization" start
    "Client generation",
    "Server verification",
    "Verifiable randomization",  # end
    # Message sizes
    "Messages sent",
    "Generate randomness",
    "Client message",
    "Server message",
    "Verifiable randomization",
]

HEADERS = [
    # ZKP statistics
    "Number of constraints",
    "Proving key size (b)",
    "Verifying key size (b)",
    # "Generate randomness" start
    "Client generation (ms)",
    "Server generation (ms)",
    "Client verification (ms)",
    "Generate randomness (ms)",  # end
    "Trusted environment computation (ms)",
    # "Verifiable randomization" start
    "Client generation (ms)",
    "Server verification (ms)",
    "Verifiable randomization (ms)",  # end
    # Message sizes
    "Messages sent (b)",
    "Generate randomness (b)",
    "Client message (b)",
    "Server message (b)",
    "Verifiable randomization (b)",
]

if __name__ == "__main__":
    datetime = sys.argv[1]

    input_file_directory = "./results/raw/benches/"
    output_file_directory = "./results/parsed/benches/"
    if not os.path.exists(output_file_directory):
        os.makedirs(output_file_directory)

    median_file_name = f"{output_file_directory}{datetime}_medians.csv"
    mean_file_name = f"{output_file_directory}{datetime}_means.csv"
    all_medians = []
    all_means = []

    for protocol_name in PROTOCOL_NAMES:
        file_name = f"{datetime}_bench_{protocol_name}"
        input_file_name = f"{input_file_directory}{file_name}.txt"
        output_file_name = f"{output_file_directory}{file_name}.csv"
        timing_and_size_data_all = []
        with open(input_file_name, 'r') as input_file:
            measurement_step_index = 0
            timing_and_size_data_one_run = []
            measurement_phase_started = False
            messages_sent_found = False
            for line in input_file.readlines():
                if line == "--- START MEASUREMENTS ---\n":
                    measurement_phase_started = True
                if not measurement_phase_started:
                    continue
                if messages_sent_found:
                    assert MEASUREMENT_STEPS[measurement_step_index] in line
                    size_text = line.split(' ')[-1].rstrip()
                    size_match = re.fullmatch(r"(?P<size>\d+)b", size_text)
                    size_text = size_match["size"]
                    timing_and_size_data_one_run.append(size_text)
                    measurement_step_index += 1
                    measurement_step_index %= len(MEASUREMENT_STEPS)
                    if measurement_step_index == 0:
                        timing_and_size_data_all.append(timing_and_size_data_one_run[:])
                        timing_and_size_data_one_run = []
                        messages_sent_found = False
                if "End:" in line:
                    if MEASUREMENT_STEPS[measurement_step_index] in line:
                        time_text = line.split(" ")[-1].lstrip(".").rstrip()
                        time_match = re.fullmatch(r"(?P<duration>[\d.]+)(?P<unit>Â?[µm]?s)", time_text)
                        time_value = float(time_match["duration"])
                        time_unit = time_match["unit"]
                        # scale everything to µs
                        if time_unit == "s":
                            time_value *= 1000
                        elif time_unit in ["Âµs", "µs"]:
                            time_value /= 1000
                        else:
                            assert time_unit == "ms"
                        timing_and_size_data_one_run.append("{:.5f}".format(round(time_value, 5)))
                        measurement_step_index += 1
                if "Messages sent:" in line:
                    messages_sent_found = True
                    size_text = line.split(' ')[-1].rstrip()
                    size_match = re.fullmatch(r"(?P<size>\d+)b", size_text)
                    size_text = size_match["size"]
                    timing_and_size_data_one_run.append(size_text)
                    measurement_step_index += 1
                if measurement_step_index <= 2 and MEASUREMENT_STEPS[measurement_step_index] in line:
                    size_text = line.split(' ')[-1].rstrip()
                    if measurement_step_index != 0:
                        size_match = re.fullmatch(r"(?P<size>\d+)b", size_text)
                        size_text = size_match["size"]
                    timing_and_size_data_one_run.append(size_text)
                    measurement_step_index += 1

        with open(output_file_name, 'w', newline='') as output_file:
            writer = csv.writer(output_file)
            writer.writerow(HEADERS)
            writer.writerows(timing_and_size_data_all)

        all_data = pandas.read_csv(output_file_name)
        all_medians.append(
            [protocol_name] + list(map(lambda x: "{:.5f}".format(round(float(x), 5)), all_data.median().values)))
        all_means.append(
            [protocol_name] + list(map(lambda x: "{:.5f}".format(round(float(x), 5)), all_data.mean().values)))

    with open(median_file_name, 'w', newline='') as median_file:
        writer = csv.writer(median_file)
        writer.writerow(["Name"] + HEADERS)
        writer.writerows(all_medians)

    with open(mean_file_name, 'w', newline='') as mean_file:
        writer = csv.writer(mean_file)
        writer.writerow(["Name"] + HEADERS)
        writer.writerows(all_means)
