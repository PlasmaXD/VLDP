import os
import sys
import pandas
import matplotlib.pyplot as plt

PROTOCOL_NAMES = ["base_histogram", "expand_histogram", "shuffle_histogram", "base_real", "expand_real", "shuffle_real"]

RANDOMNESS_VALUES = (32, 64, 128, 256, 512, 1024)
RANDOMNESS_LABELS = [f"r_{r}/" for r in RANDOMNESS_VALUES]
MT_VALUES = tuple(range(2, 12))
MT_LABELS = [f"m_{m}/" for m in MT_VALUES]

if __name__ == "__main__":
    datetime = sys.argv[1]

    input_file_directory = "./results/parsed/additional_benches/"

    for dir_, x_values, filter_labels, x_label in zip(
            ("./results/plots/randomness", "./results/plots/merkle_tree"),
            (RANDOMNESS_VALUES, MT_VALUES),
            (RANDOMNESS_LABELS, MT_LABELS),
            (r"$|\rho|$ (bytes)", r"$d_\textsf{MT}$")):
        if not os.path.exists(dir_):
            os.makedirs(dir_)

        SMALL_SIZE = 12
        MEDIUM_SIZE = 14
        BIGGER_SIZE = 16

        plt.rcParams.update({
            "text.usetex": True,
        })
        plt.rc('font', size=SMALL_SIZE)  # controls default text sizes
        plt.rc('axes', titlesize=MEDIUM_SIZE)  # fontsize of the axes title
        plt.rc('axes', labelsize=MEDIUM_SIZE)  # fontsize of the x and y labels
        plt.rc('xtick', labelsize=SMALL_SIZE)  # fontsize of the tick labels
        plt.rc('ytick', labelsize=SMALL_SIZE)  # fontsize of the tick labels
        plt.rc('legend', fontsize=MEDIUM_SIZE)  # legend fontsize
        plt.rc('figure', titlesize=BIGGER_SIZE)  # fontsize of the figure title

        for title, column in zip(
                ("GenRand-1 (client)", "GenRand-2 (client)", "GenRand (server)", "Randomize (client)",
                 "Verify (server)", "Number of constraints"),
                ("Client | GenRand-1 (ms)", "Client | GenRand-2 (ms)", "Server | GenRand (ms)",
                 "Client | Randomize (ms)", "Server | Verify (ms)", "# constraints")):

            fig, ax = plt.subplots(tight_layout=True)
            for protocol_name in PROTOCOL_NAMES:

                if "merkle_tree" in dir_ and "expand" not in protocol_name:
                    continue
                median_file_name = f"{input_file_directory}{datetime}_{protocol_name}_medians.csv"
                all_medians = pandas.read_csv(median_file_name)

                y_values = all_medians.loc[all_medians["Parameter_value"].isin(filter_labels)][column].values
                if "histogram" in protocol_name:
                    marker = "|"
                else:
                    marker = "x"
                plt.plot(x_values, y_values, label=protocol_name.replace("_", "-"),
                         marker=marker)

            plt.title(title)
            ax.set_xlabel(x_label)
            if title == "Number of constraints":
                ax.set_ylabel("\# constraints")
            else:
                ax.set_ylabel("Runtime (ms)")
            plt.legend()

            plt.savefig(f"{dir_}/{title}.pdf")
