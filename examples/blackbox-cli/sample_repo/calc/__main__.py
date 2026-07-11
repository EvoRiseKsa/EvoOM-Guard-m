import sys

from calc.ops import add, mul


def main(argv):
    _, op, a, b = argv
    fn = add if op == "add" else mul
    print(fn(int(a), int(b)))


if __name__ == "__main__":
    main(sys.argv)
