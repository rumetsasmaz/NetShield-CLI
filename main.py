import sys


def main():
    if len(sys.argv) > 1:
        from netshield.cli import run
        sys.exit(run(sys.argv[1:]))
    from netshield.menu import run_menu
    run_menu()


if __name__ == "__main__":
    main()
