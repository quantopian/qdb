import qdb
import pdb

def main():
    qdb.set_trace(uuid_fn=lambda:'qdb')
    # pdb.set_trace()
    test = 10
    print 'hi'
    f()
    print 'back in main'


def f():
    print 'I am in f'
    g = 3
    print g


if __name__ == '__main__':
    main()
