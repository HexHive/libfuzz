#!/usr/bin/env python3

from collections import Counter, defaultdict
import argparse


class File:
    """
    Represents a file with its filename and lines.
    """
    def total_visits(self):
        return sum(self.lines.values())

    def __init__(self):
        self.filename = ""
        self.lines = Counter()
    
    def unique_visits(self, fileB):
        d = defaultdict(lambda: 1, {})
        [d[v] for v in set(self.lines.keys()) - set(fileB.lines.keys())]
        diff = File()
        diff.lines = d
        diff.filename = self.filename
        return diff

    def merge(self, fileB):
        for k, v in fileB.lines.items():
            self.lines[k] += v

class Library:
    """
    Represents a library with files and their coverage information.
    """
    def __init__(self, log_file_path):
        self.files = {}
        self.log_file_path = log_file_path
        self.parse_log_file()

    def parse_log_file(self):
        """
        Parses the log file and populates the library with file coverage information.
        The log file should contain lines in the following format:
        - /home/<username>/path/to/file.py
        - line_number | visits
        """
        with open(self.log_file_path, 'r') as log_file:
            current_file = None
            for line in log_file:
                line = line.strip()

                if line.startswith('/'):
                    if current_file is not None:
                        self.files[current_file.filename] = current_file
                    current_file = File()
                    current_file.filename = line

                elif current_file is not None and len(line) > 0:
                    line_parts = line.split('|')
                    line_number = int(line_parts[0].strip())
                    visits = line_parts[1].strip()
                    # Convert visits to a numeric value based on the suffix (k, M, B)
                    if visits.endswith('k'):
                        visits = float(visits[:-1]) * 1000
                    elif visits.endswith('M'):
                        visits = float(visits[:-1]) * 1000000
                    elif visits.endswith('B'):
                        visits = float(visits[:-1]) * 1000000000
                    else:
                        visits = float(visits.strip() or 0)
                    if visits > 0:
                        current_file.lines[line_number] = visits

        if current_file is not None:
            self.files[current_file.filename] = current_file

    def unique_visits(self, libB):
        unique = 0
        for filename, file in self.files.items():
            for filenameB, fileB in libB.files.items():
                if filename.split('/')[-1] == filenameB.split('/')[-1]:
                    d=file.unique_visits(fileB)
                    unique += d.total_visits()
        return unique
    
    def merge(self, libB):
        for filename, file in self.files.items():
            for filenameB, fileB in libB.files.items():
                if filename.split('/')[-1] == filenameB.split('/')[-1]:
                    file.merge(fileB)
        return self



def main():
    """
    Main function to calculate and print total visits and visits at line 10 for each file.
    """
    parser = argparse.ArgumentParser(description='Calculate unique coverage for a folder.')
    parser.add_argument('utopia_folder', type=str, help='Path to the folder containing coverage logs')
    parser.add_argument('libfuzz_folder', type=str, help='Path to the folder containing coverage logs')
    parser.add_argument('merge_iteration', type=bool, help='Merge the coverage of the different runs')
    args = parser.parse_args()

    utopia_coverage ={}
    for target in os.listdir(args.utopia_folder):
        target_path = os.path.join(args.folder, target)
        runs = []
        for iteration in os.listdir(target_path):
            iteration = os.path.join(target_path, iteration)
            if 'show' in os.listdir(target_path):
                library_log_file_path = os.path.join(iteration, 'show')
                runs.append(Library(library_log_file_path))
                break
        if args.merge_iteration:
            for run in runs[1:]:
                runs[0].merge(run)
        utopia_coverage[target] = runs[0]
    
    libfuzz_coverage ={}
    for target in os.listdir(args.libfuzz_folder):
        target_path = os.path.join(args.folder, target)
        runs = []
        for iteration in os.listdir(target_path):
            iteration = os.path.join(target_path, iteration)
            if 'show' in os.listdir(target_path):
                library_log_file_path = os.path.join(iteration, 'show')
                runs.append(Library(library_log_file_path))
                break
        if args.merge_iteration:
            for run in runs[1:]:
                runs[0].merge(run)
        libfuzz_coverage[target] = runs[0]
    
    for common_target in set(utopia_coverage.keys()).intersection(set(libfuzz_coverage.keys())):
        unique_utopia = utopia_coverage[common_target].unique_visits(libfuzz_coverage[common_target])
        print("Utopia Unique coverage for {} is {}".format(common_target, unique_utopia))
        unique_libfuzz = libfuzz_coverage[common_target].unique_visits(utopia_coverage[common_target])
        print("Libfuzz Unique coverage for {} is {}".format(common_target, unique_libfuzz))
    

if __name__ == "__main__":
    main()
