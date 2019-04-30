#!/usr/bin/env python
import os


def main():
    path = '.'
    count = 0
    for name, folders, files in os.walk(path, topdown=False):
        for file in files:
            if file.endswith('.pyc') \
               or file.endswith('~') \
               or file.endswith('.pyo'):
                count += 1
                os.remove(os.path.join(name, file))
        for folder in folders:
            if folder == '__pycache__':
                try:
                    os.rmdir(os.path.join(name, folder))
                except OSError:
                    pass

    print("Deleted %s files" % count)


if __name__ == "__main__":
    main()
