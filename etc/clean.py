import os


def main():
    path = '.'
    count = 0
    for name, folders, files in os.walk(path):
        for file in files:
            if file.endswith('.pyc') \
               or file.endswith('~') \
               or file.endswith('.pyo'):
                count += 1
                os.remove(os.path.join(name, file))

    print "Deleted %s files" % count


if __name__ == "__main__":
    main()
